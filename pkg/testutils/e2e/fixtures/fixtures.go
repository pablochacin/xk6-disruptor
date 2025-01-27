// Package fixtures implements helpers for setting e2e tests
package fixtures

import (
	"github.com/grafana/xk6-disruptor/pkg/testutils/kubernetes/builders"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// BuildHttpbinPod returns the definition for deploying Httpbin as a Pod
func BuildHttpbinPod() *corev1.Pod {
	c := *builders.NewContainerBuilder("httpbin").
		WithImage("kennethreitz/httpbin").
		WithPullPolicy(corev1.PullIfNotPresent).
		WithPort("http", 80).
		Build()

	return builders.NewPodBuilder("httpbin").
		WithLabels(
			map[string]string{
				"app": "httpbin",
			},
		).
		WithContainer(c).
		Build()
}

// BuildGrpcpbinPod returns the definition for deploying grpcbin as a Pod
func BuildGrpcpbinPod() *corev1.Pod {
	c := *builders.NewContainerBuilder("grpcbin").
		WithImage("moul/grpcbin").
		WithPullPolicy(corev1.PullIfNotPresent).
		WithPort("grpc", 9000).
		Build()

	return builders.NewPodBuilder("grpcbin").
		WithLabels(
			map[string]string{
				"app": "grpcbin",
			},
		).
		WithContainer(c).
		Build()
}

// BuildHttpbinService returns a Service definition that exposes httpbin pods
func BuildHttpbinService() *corev1.Service {
	return builders.NewServiceBuilder("httpbin").
		WithSelector(
			map[string]string{
				"app": "httpbin",
			},
		).
		WithPorts(
			[]corev1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromString("http"),
				},
			},
		).
		Build()
}

// BuildGrpcbinService returns a Service definition that exposes grpcbin pods at the node port 30000
func BuildGrpcbinService() *corev1.Service {
	return builders.NewServiceBuilder("grpcbin").
		WithSelector(
			map[string]string{
				"app": "grpcbin",
			},
		).
		WithServiceType(corev1.ServiceTypeClusterIP).
		WithAnnotation("projectcontour.io/upstream-protocol.h2c", "9000").
		WithPorts(
			[]corev1.ServicePort{
				{
					Name: "grpc",
					Port: 9000,
				},
			},
		).
		Build()
}

// BuildBusyBoxPod returns the definition of a Pod that runs busybox and waits 5min before completing
func BuildBusyBoxPod() *corev1.Pod {
	c := *builders.NewContainerBuilder("busybox").
		WithImage("busybox").
		WithPullPolicy(corev1.PullIfNotPresent).
		WithCommand("sleep", "300").
		Build()

	return builders.NewPodBuilder("busybox").
		WithLabels(
			map[string]string{
				"app": "busybox",
			},
		).
		WithContainer(c).
		Build()
}

// BuildPausedPod returns the definition of a Pod that runs the paused image in a container
// creating a "no-op" dummy Pod.
func BuildPausedPod() *corev1.Pod {
	c := *builders.NewContainerBuilder("paused").
		WithImage("k8s.gcr.io/pause").
		WithPullPolicy(corev1.PullIfNotPresent).
		Build()

	return builders.NewPodBuilder("paused").
		WithContainer(c).
		Build()
}

// BuildNginxPod returns the definition of a Pod that runs Nginx
func BuildNginxPod() *corev1.Pod {
	c := *builders.NewContainerBuilder("busybox").
		WithImage("nginx").
		WithPullPolicy(corev1.PullIfNotPresent).
		WithPort("http", 80).
		Build()

	return builders.NewPodBuilder("nginx").
		WithLabels(
			map[string]string{
				"app": "nginx",
			},
		).
		WithContainer(c).
		Build()
}

// BuildNginxService returns the definition of a Service that exposes the nginx pod(s)
func BuildNginxService() *corev1.Service {
	return builders.NewServiceBuilder("nginx").
		WithSelector(
			map[string]string{
				"app": "nginx",
			},
		).
		WithPorts(
			[]corev1.ServicePort{
				{
					Name: "http",
					Port: 80,
				},
			},
		).
		Build()
}
