// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package container provides utilities for interacting with container runtimes
// via CRI (Container Runtime Interface) to retrieve container and pod information.
package container

import (
	"context"
	"errors"
	"fmt"
	"time"

	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// GetContainerInfo retrieves pod identity for a given container ID via on-demand query.
func GetContainerInfo(containerID string) (string, string, string, error) {
	conn, err := createGRPCConnection()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create connection: %w", err)
	}
	defer conn.Close()

	client := runtimeapi.NewRuntimeServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	statusReq := &runtimeapi.ContainerStatusRequest{ContainerId: containerID}

	statusResp, err := client.ContainerStatus(ctx, statusReq)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get container status: %w", err)
	}

	if statusResp.GetStatus() == nil {
		return "", "", "", errors.New("container status is empty")
	}

	labels := statusResp.GetStatus().GetLabels()
	podNamespace := labels["io.kubernetes.pod.namespace"]

	podName := labels["io.kubernetes.pod.name"]
	if podName == "" {
		return "", "", "", errors.New(
			"cannot find pod name (io.kubernetes.pod.name) in container labels",
		)
	}

	if podNamespace == "" {
		return "", "", "", errors.New(
			"cannot find pod namespace (io.kubernetes.pod.namespace) in container labels",
		)
	}

	podUID := labels["io.kubernetes.pod.uid"]
	if podUID == "" {
		return "", "", "", errors.New(
			"cannot find pod uid (io.kubernetes.pod.uid) in container labels",
		)
	}

	return podName, podNamespace, podUID, nil
}

// createGRPCConnection establishes a gRPC connection to the container runtime
func createGRPCConnection() (*grpc.ClientConn, error) {
	endpoints := []string{
		"unix:///var/run/containerd/containerd.sock",
		"unix:///run/containerd/containerd.sock",
		"unix:///var/run/crio/crio.sock",
		"unix:///var/run/dockershim.sock",
	}

	var lastErr error
	for _, endpoint := range endpoints {
		conn, err := grpc.NewClient(
			endpoint,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			lastErr = err
			continue
		}

		if err := waitForConnectionReady(conn, 5*time.Second); err == nil {
			legacy.L.WithField("endpoint", endpoint).
				Info("Successfully connected to container runtime")
			return conn, nil
		}

		lastErr = fmt.Errorf("connection timeout for endpoint %s", endpoint)
		if closeErr := conn.Close(); closeErr != nil {
			legacy.L.WithError(closeErr).
				WithField("endpoint", endpoint).
				Debug("Failed to close unsuccessful runtime connection")
		}
	}

	return nil, fmt.Errorf("failed to connect to any container runtime: %w", lastErr)
}

func waitForConnectionReady(conn *grpc.ClientConn, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn.Connect()

	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return nil
		}

		if state == connectivity.Shutdown {
			return errors.New("runtime connection shut down")
		}

		if !conn.WaitForStateChange(ctx, state) {
			return fmt.Errorf("runtime connection did not become ready from state %s", state)
		}
	}
}
