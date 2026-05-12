SHELL := /bin/bash

NAMESPACE ?= k8s-tests-dev
PROFILE   ?= dev
RELEASE   ?= xrootd-servers
INFRA     ?= test-infra
NODE_COUNT ?= 3
AUTH_MODE ?= none
CLUSTER_TYPE ?= auto  # auto, minikube, kind
IMAGE_TAG ?= latest

.PHONY: all build-images cluster-start deploy-deploy-test test teardown help \
        images-minikube images-kind load-images clean

all: build-images cluster-start deploy-infra deploy-servers run-tests

build-images: images-local

images-local:
	for img in server client test-runner; do \
		docker build -t nginx-xrootd-$$img:$(IMAGE_TAG) \
			-f Dockerfiles/$$img/Dockerfile .. || exit 1; \
	done

cluster-start:
	bash scripts/setup-cluster.sh $(NODE_COUNT) 4 8192 $(CLUSTER_TYPE) 120s

deploy-infra:
	helm upgrade --install cert-manager jetstack/cert-manager \
		--namespace cert-manager --create-namespace \
		--set crds.enabled=true || true
	helm upgrade --install $(INFRA) ./test-infra-helm \
		--namespace $(NAMESPACE) --create-namespace \
		-f ./test-infra-helm/values.yaml

deploy-servers: deploy-infra
	if [ "$(CLUSTER_TYPE)" = "kind" ]; then \
		KUBECONFIG=$$(kind get kubeconfig-path --name nginx-xrootd-test 2>/dev/null) helm upgrade --install $(RELEASE) ./server-helm \
			--namespace $(NAMESPACE) --create-namespace \
			-f ./server-helm/values.$(PROFILE).yaml \
			--set image.pullPolicy=Never; \
	else \
		helm upgrade --install $(RELEASE) ./server-helm \
			--namespace $(NAMESPACE) --create-namespace \
			-f ./server-helm/values.$(PROFILE).yaml; \
	fi

run-tests: deploy-servers
	kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=server \
		-n $(NAMESPACE) --timeout=300s || true
	helm upgrade --install test-job ./test-infra-helm \
		--namespace $(NAMESPACE) \
		--set job.image=nginx-xrootd-test-runner:$(IMAGE_TAG) \
		--set job.imagePullPolicy=Never \
		--set job.authMode=$(AUTH_MODE) || true

test: run-tests
	kubectl wait --for=condition=complete job/test-job \
		-n $(NAMESPACE) --timeout=1800s || true
	mkdir -p /tmp/k8s-test-results && kubectl cp $(NAMESPACE)/test-runner:/test-results/*.xml /tmp/k8s-test-results/ 2>/dev/null || true
	if ls /tmp/k8s-test-results/*.xml &>/dev/null; then \
		python3 test-runner/aggregate_results.py --results-dir /tmp/k8s-test-results -o /tmp/test-summary.json && cat /tmp/test-summary.json; \
	else \
		kubectl logs -l app.kubernetes.io/component=test-runner -n $(NAMESPACE) --tail=-1 || true; \
	fi

teardown-%:
	helm uninstall $(RELEASE) --namespace $(*) 2>/dev/null || true
	helm uninstall $(INFRA) --namespace $(*) 2>/dev/null || true
	kubectl delete namespace $(*) --wait --timeout=120s 2>/dev/null || true
if [ "$(CLUSTER_TYPE)" = "kind" ]; then \
		kind delete cluster --name nginx-xrootd-test 2>/dev/null || true; \
	else \
		minikube delete --all 2>/dev/null || true; \
	fi

teardown-all: teardown-dev teardown-staging teardown-perf

help:
	@echo "Targets:"
	@echo "  build-images     Build container images locally"
	@echo "  cluster-start    Bootstrap K8s cluster (minikube or kind, auto-detect)"
	@echo "  deploy-infra     Deploy PKI/test infrastructure via Helm"
	@echo "  deploy-servers   Deploy nginx-xrootd server nodes via Helm"
	@echo "  run-tests        Deploy test runner Job and wait for completion"
	@echo "  test             Run tests + aggregate results (includes run-tests)"
	@echo "  teardown-dev     Clean up dev namespace and cluster"
	@echo "  teardown-all     Clean up all namespaces (dev, staging, perf)"
	@echo ""
	@echo "Variables:"
	@echo "  NAMESPACE=k8s-tests-dev   Kubernetes namespace"
	@echo "  PROFILE=dev               Test profile (dev, dev-gsi, staging, perf)"
	@echo "  NODE_COUNT=3              Number of cluster nodes"
	@echo "  AUTH_MODE=none            Auth mode for tests (none, gsi, token)"
	@echo "  CLUSTER_TYPE=auto         Cluster type: auto, minikube, or kind"
	@echo "  IMAGE_TAG=latest          Container image tag"
