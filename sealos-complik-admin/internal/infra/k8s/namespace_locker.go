package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

const (
	NamespaceLockLabelKey    = "block.sealos.io/locked"
	NamespaceLockLabelValue  = "true"
	defaultKubeConfigEnvName = "KUBECONFIG"
)

type NamespaceLocker interface {
	EnsureLocked(ctx context.Context, namespace string) (bool, error)
	EnsureUnlocked(ctx context.Context, namespace string) (bool, error)
}

type namespaceLocker struct {
	client kubernetes.Interface
}

type noopNamespaceLocker struct{}

func NewNoopNamespaceLocker() NamespaceLocker {
	return noopNamespaceLocker{}
}

// RetryableAttributionError marks a Kubernetes attribution lookup failure as
// safe to retry. Identity mismatches remain ordinary errors and fail closed.
type RetryableAttributionError struct {
	Err error
}

func (e RetryableAttributionError) Error() string {
	if e.Err == nil {
		return "kubernetes attribution lookup failed"
	}
	return e.Err.Error()
}

func (e RetryableAttributionError) Unwrap() error {
	return e.Err
}

func (RetryableAttributionError) Retryable() bool {
	return true
}

func NewNamespaceLocker() (NamespaceLocker, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	return &namespaceLocker{client: client}, nil
}

func (l *namespaceLocker) EnsureLocked(ctx context.Context, namespace string) (bool, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	if !AllowsTenantNamespaceLock(trimmedNamespace) {
		return false, fmt.Errorf("namespace %q is not eligible for lock", trimmedNamespace)
	}

	return l.ensureLabel(ctx, trimmedNamespace, true)
}

func (l *namespaceLocker) EnsureUnlocked(ctx context.Context, namespace string) (bool, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	if !AllowsTenantNamespaceLock(trimmedNamespace) {
		return false, fmt.Errorf("namespace %q is not eligible for unlock", trimmedNamespace)
	}

	return l.ensureLabel(ctx, trimmedNamespace, false)
}

// CheckReady verifies Kubernetes API connectivity and the permissions needed
// by the namespace locker.
func (l *namespaceLocker) CheckReady(ctx context.Context) error {
	if l == nil || l.client == nil {
		return errors.New("kubernetes client is not initialized")
	}

	_, err := l.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return fmt.Errorf("check kubernetes readiness: %w", err)
	}

	return nil
}

func (l *namespaceLocker) VerifyContainer(
	ctx context.Context,
	namespace string,
	podName string,
	podUID string,
	containerID string,
	nodeName string,
) error {
	namespace = strings.TrimSpace(namespace)
	podName = strings.TrimSpace(podName)
	podUID = strings.TrimSpace(podUID)
	containerID = normalizeContainerID(containerID)
	nodeName = strings.TrimSpace(nodeName)
	if namespace == "" || podName == "" || podUID == "" || containerID == "" || nodeName == "" ||
		strings.EqualFold(nodeName, "unknown") {
		return errors.New("complete pod attribution is required")
	}

	pod, err := l.client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return RetryableAttributionError{
				Err: fmt.Errorf("get attributed pod: %w", err),
			}
		}
		return fmt.Errorf("get attributed pod: %w", err)
	}
	if string(pod.UID) != podUID {
		return errors.New("pod uid does not match")
	}
	if pod.Spec.NodeName != nodeName {
		return errors.New("pod node does not match")
	}

	statuses := append(
		append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...),
		append(pod.Status.ContainerStatuses, pod.Status.EphemeralContainerStatuses...)...,
	)
	for _, status := range statuses {
		if normalizeContainerID(status.ContainerID) == containerID {
			return nil
		}
	}

	return errors.New("container does not belong to pod")
}

func normalizeContainerID(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.Index(value, "://"); index >= 0 {
		return value[index+3:]
	}
	return value
}

func (l *namespaceLocker) ensureLabel(
	ctx context.Context,
	namespace string,
	lock bool,
) (bool, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	if trimmedNamespace == "" {
		return false, errors.New("namespace is required")
	}

	changed := false

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		target, err := l.client.CoreV1().
			Namespaces().
			Get(ctx, trimmedNamespace, metav1.GetOptions{})
		if err != nil {
			if !lock && apierrors.IsNotFound(err) {
				return nil
			}

			return err
		}

		target = target.DeepCopy()

		labels := target.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}

		if lock {
			if labels[NamespaceLockLabelKey] == NamespaceLockLabelValue {
				return nil
			}

			labels[NamespaceLockLabelKey] = NamespaceLockLabelValue
			target.SetLabels(labels)

			changed = true
			_, err = l.client.CoreV1().Namespaces().Update(ctx, target, metav1.UpdateOptions{})

			return err
		}

		if _, ok := labels[NamespaceLockLabelKey]; !ok {
			return nil
		}

		delete(labels, NamespaceLockLabelKey)
		target.SetLabels(labels)

		changed = true
		_, err = l.client.CoreV1().Namespaces().Update(ctx, target, metav1.UpdateOptions{})

		return err
	})
	if err != nil {
		return false, err
	}

	return changed, nil
}

func loadConfig() (*rest.Config, error) {
	if kubeconfig := strings.TrimSpace(os.Getenv(defaultKubeConfigEnvName)); kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".kube", "config")
		if _, statErr := os.Stat(path); statErr == nil {
			return clientcmd.BuildConfigFromFlags("", path)
		}
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubernetes config: %w", err)
	}

	return cfg, nil
}

func (noopNamespaceLocker) EnsureLocked(context.Context, string) (bool, error) {
	return false, nil
}

func (noopNamespaceLocker) EnsureUnlocked(context.Context, string) (bool, error) {
	return false, nil
}

func (noopNamespaceLocker) CheckReady(context.Context) error {
	return nil
}
