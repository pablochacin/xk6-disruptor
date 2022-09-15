package disruptors

import (
	"sort"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/grafana/xk6-disruptor/pkg/kubernetes"
	"github.com/grafana/xk6-disruptor/pkg/testutils/kubernetes/builders"
)

const testNamespace = "default"

var (
	podWithoutLabels = builders.NewPodBuilder("pod-without-labels").
		WithNamespace(testNamespace).
		WithLabels(map[string]string{}).
		Build()

	podWithAppLabel = builders.NewPodBuilder("pod-with-app-label").
		WithNamespace(testNamespace).
		WithLabels(map[string]string{
			"app": "test",
		}).
		Build()

	podWithAppLabelInAnotherNs = builders.NewPodBuilder("pod-with-app-label").
		WithNamespace("anotherNamespace").
		WithLabels(map[string]string{
			"app": "test",
		}).
		Build()

	anotherPodWithAppLabel = builders.NewPodBuilder("another-pod-with-app-label").
		WithNamespace(testNamespace).
		WithLabels(map[string]string{
			"app": "test",
		}).
		Build()

	podWithProdEnvLabel = builders.NewPodBuilder("pod-with-prod-label").
		WithNamespace(testNamespace).
		WithLabels(map[string]string{
			"app": "test",
			"env": "prod",
		}).
		Build()

	podWithDevEnvLabel = builders.NewPodBuilder("pod-with-dev-label").
		WithNamespace(testNamespace).
		WithLabels(map[string]string{
			"app": "test",
			"env": "dev",
		}).
		Build()
)

func compareSortedArrays(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	if len(a) == 0 {
		return true
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func Test_PodSelectorWithLabels(t *testing.T) {
	testCases := []struct {
		title        string
		pods         []runtime.Object
		labels       map[string]string
		exclude      map[string]string
		expectError  bool
		expectedPods []string
	}{
		{
			title: "No matching pod",
			pods: []runtime.Object{
				podWithoutLabels,
			},
			labels: map[string]string{
				"app": "test",
			},
			expectError:  true,
			expectedPods: []string{},
		},
		{
			title: "No matching namespace",
			pods: []runtime.Object{
				podWithAppLabelInAnotherNs,
			},
			labels: map[string]string{
				"app": "test",
			},
			expectError:  true,
			expectedPods: []string{},
		},
		{
			title: "one matching pod",
			pods: []runtime.Object{
				podWithAppLabel,
			},
			labels: map[string]string{
				"app": "test",
			},
			expectError: false,
			expectedPods: []string{
				podWithAppLabel.Name,
			},
		},
		{
			title: "multiple matching pods",
			pods: []runtime.Object{
				podWithAppLabel,
				anotherPodWithAppLabel,
			},
			labels: map[string]string{
				"app": "test",
			},
			expectError: false,
			expectedPods: []string{
				podWithAppLabel.Name,
				anotherPodWithAppLabel.Name,
			},
		},
		{
			title: "multiple selector labels",
			pods: []runtime.Object{
				podWithAppLabel,
				podWithDevEnvLabel,
				podWithProdEnvLabel,
			},
			labels: map[string]string{
				"app": "test",
				"env": "dev",
			},
			expectError: false,
			expectedPods: []string{
				podWithDevEnvLabel.Name,
			},
		},
		{
			title: "exclude environment",
			pods: []runtime.Object{
				podWithDevEnvLabel,
				podWithProdEnvLabel,
			},
			labels: map[string]string{
				"app": "test",
			},
			exclude: map[string]string{
				"env": "prod",
			},
			expectError: false,
			expectedPods: []string{
				podWithDevEnvLabel.Name,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			client := fake.NewSimpleClientset(tc.pods...)
			k, _ := kubernetes.NewFakeKubernetes(client)
			selector := PodSelector{
				Namespace: testNamespace,
				Select: PodAttributes{
					Labels: tc.labels,
				},
				Exclude: PodAttributes{
					Labels: tc.exclude,
				},
			}

			targets, err := selector.GetTargets(k)
			if tc.expectError && err == nil {
				t.Errorf("should had failed")
				return
			}

			if !tc.expectError && err != nil {
				t.Errorf("failed: %v", err)
				return
			}

			if tc.expectError && err != nil {
				return
			}

			sort.Strings(tc.expectedPods)
			sort.Strings(targets)
			if !compareSortedArrays(tc.expectedPods, targets) {
				t.Errorf("result does not match expected value. Expected: %s\nActual: %s\n", tc.expectedPods, targets)
				return
			}
		})
	}
}
