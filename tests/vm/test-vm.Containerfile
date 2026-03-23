FROM localhost/hypervisor-bootc:latest

# Enable passwordless sudo for test user
RUN echo '%wheel ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wheel-nopasswd && \
    chmod 0440 /etc/sudoers.d/wheel-nopasswd

# Allow pulling from local insecure registry
RUN mkdir -p /etc/containers/registries.conf.d && \
    printf '[[registry]]\nlocation = "192.168.0.64:5000"\ninsecure = true\n' \
    > /etc/containers/registries.conf.d/local-registry.conf

# Layer test workload configs on top of the base image
COPY --link test-workloads.d/ /etc/workloads.d/

# Install the VM test script
COPY --link run-vm-tests.sh /usr/local/bin/run-vm-tests
RUN chmod 0755 /usr/local/bin/run-vm-tests
