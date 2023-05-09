package fixtures

import (
	"context"
	"fmt"
	"time"

	"github.com/grafana/xk6-disruptor/pkg/kubernetes"
	"github.com/grafana/xk6-disruptor/pkg/testutils/kubernetes/builders"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// BuildHttpbinPod returns the definition for deploying Httpbin as a Pod
func BuildHttpbinPod(namespace string) *corev1.Pod {
	c := *builders.NewContainerBuilder("httpbin").
		WithImage("kennethreitz/httpbin").
		WithPullPolicy(corev1.PullIfNotPresent).
		WithPort("http", 80).
		Build()

	return builders.NewPodBuilder("httpbin").
		WithNamespace(namespace).
		WithLabels(
			map[string]string{
				"app": "httpbin",
			},
		).
		WithContainer(c).
		Build()
}

// BuildGrpcpbinPod returns the definition for deploying grpcbin as a Pod
func BuildGrpcpbinPod(namespace string) *corev1.Pod {
	c := *builders.NewContainerBuilder("grpcbin").
		WithImage("moul/grpcbin").
		WithPullPolicy(corev1.PullIfNotPresent).
		WithPort("grpc", 9000).
		Build()

	return builders.NewPodBuilder("grpcbin").
		WithNamespace(namespace).
		WithLabels(
			map[string]string{
				"app": "grpcbin",
			},
		).
		WithContainer(c).
		Build()
}

// BuildHttpbinService returns a Service definition that exposes httpbin pods
func BuildHttpbinService(namespace string) *corev1.Service {
	return builders.NewServiceBuilder("httpbin").
		WithNamespace(namespace).
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
func BuildGrpcbinService(namespace string, nodePort uint) *corev1.Service {
	return builders.NewServiceBuilder("grpcbin").
		WithNamespace(namespace).
		WithSelector(
			map[string]string{
				"app": "grpcbin",
			},
		).
		WithServiceType(corev1.ServiceTypeNodePort).
		WithPorts(
			[]corev1.ServicePort{
				{
					Name:     "grpc",
					Port:     9000,
					NodePort: int32(nodePort),
				},
			},
		).
		Build()
}

// BuildBusyBoxPod returns the definition of a Pod that runs busybox and waits 5min before completing
func BuildBusyBoxPod(namespace string) *corev1.Pod {
	c := *builders.NewContainerBuilder("busybox").
		WithImage("busybox").
		WithPullPolicy(corev1.PullIfNotPresent).
		WithCommand("sleep", "300").
		Build()

	return builders.NewPodBuilder("busybox").
		WithNamespace(namespace).
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
func BuildPausedPod(namespace string) *corev1.Pod {
	c := *builders.NewContainerBuilder("paused").
		WithImage("k8s.gcr.io/pause").
		WithPullPolicy(corev1.PullIfNotPresent).
		Build()

	return builders.NewPodBuilder("paused").
		WithNamespace(namespace).
		WithContainer(c).
		Build()
}

// BuildNginxPod returns the definition of a Pod that runs Nginx
func BuildNginxPod(namespace string) *corev1.Pod {
	c := *builders.NewContainerBuilder("busybox").
		WithImage("nginx").
		WithPullPolicy(corev1.PullIfNotPresent).
		WithPort("http", 80).
		Build()

	return builders.NewPodBuilder("nginx").
		WithNamespace(namespace).
		WithLabels(
			map[string]string{
				"app": "nginx",
			},
		).
		WithContainer(c).
		Build()
}

// BuildNginxService returns the definition of a Service that exposes the nginx pod(s)
func BuildNginxService(namespace string) *corev1.Service {
	return builders.NewServiceBuilder("nginx").
		WithNamespace(namespace).
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

// ExposeService exposes a service in the given namespace and waits for it to be ready
func ExposeService(k8s kubernetes.Kubernetes, ns string, svc *corev1.Service, timeout time.Duration) error {
	_, err := k8s.Client().CoreV1().Services(ns).Create(
		context.TODO(),
		svc,
		metav1.CreateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to create service %s: %w", svc.Name, err)
	}

	// wait for the service to be ready for accepting requests
	err = k8s.ServiceHelper(ns).WaitServiceReady(context.TODO(), svc.Name, timeout)
	if err != nil {
		return fmt.Errorf("error waiting for service %s: %w", svc.Name, err)
	}

	return nil
}

// RunPod creates a pod and waits it for be running
func RunPod(k8s kubernetes.Kubernetes, ns string, pod *corev1.Pod, timeout time.Duration) error {
	_, err := k8s.Client().CoreV1().Pods(ns).Create(
		context.TODO(),
		pod,
		metav1.CreateOptions{},
	)
	if err != nil {
		return fmt.Errorf("error creating pod %s: %w", pod.Name, err)
	}

	running, err := k8s.PodHelper(ns).WaitPodRunning(
		context.TODO(),
		pod.Name,
		timeout,
	)
	if err != nil {
		return fmt.Errorf("error waiting for pod %s: %w", pod.Name, err)
	}
	if !running {
		return fmt.Errorf("pod %s not ready after %f: ", pod.Name, timeout.Seconds())
	}

	return nil
}

// DeployApp deploys a pod in a namespace and exposes it as a service in a cluster
func DeployApp(
	k8s kubernetes.Kubernetes,
	ns string,
	pod *corev1.Pod,
	svc *corev1.Service,
	timeout time.Duration,
) error {
	start := time.Now()
	err := RunPod(k8s, ns, pod, timeout)
	if err != nil {
		return fmt.Errorf("failed to create pod %s in namespace %s: %w", pod.Name, ns, err)
	}

	timeLeft := timeout - time.Since(start)
	return ExposeService(k8s, ns, svc, timeLeft)
}

