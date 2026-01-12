# Hypervisor & Workload System - Ideas & Directions

> Idea capture and roadmap planning. No commitment.
> 
> Review periodically and pick what sounds interesting.

**Last Updated:** 2026-01-11

---

## Active Consideration
*Currently thinking about these*

### Workload Library - Practical Services
**Why:** Validate workload system with real services, build useful infrastructure
**Effort:** Medium (incremental, ~1 day per service)
**Value:** High (validates system, immediately useful)
**Interest:** High

**Services to implement:**
- [ ] Pi-hole (DNS/ad blocking)
- [ ] Local container registry (private image storage)
- [ ] Squid proxy (caching HTTP/rpm proxy)
- [ ] VPN web proxy (route traffic through VPN tunnel)
- [ ] Fileserver (Samba/NFS)
- [ ] Gitea or other self-hosted git
- [ ] Jellyfin (media server)
- [ ] Monitoring stack (Prometheus + Grafana)

**Next action:** Start with Pi-hole or local registry (both straightforward)

**Status:** Ready to start

---

### Gaming/Desktop Streaming
Stream games from beefy computer to thin client in another room
- **Effort:** Unknown (depends on headless display solution)
- **Value:** High (primary use case)
- **Interest:** High

**Unknowns:**
- Does headless Steam work in container?
- What display server is needed? (Xvfb, Wayland headless, virtual DRM?)
- Does Sunshine capture containerized apps properly?
- Resource limits work

**Already validated:**
- [Cosy](https://github.com/BenSmith/cosy) proves GPU-accelerated apps in containers work
- Device passthrough (GPU, audio, input) works

**Notes:**
**Next action:** Test headless Steam (with Cosy?) to validate feasibility
**Status:** Blocked on validation test


---
### Full Desktop Environments in Containers
**Why:** lots of flexibility in desktop environments, easy to add/remove, and little hypervisor pollution 
- **Complexity:** High (display server, session management, deep integration)
- **Alternative:** Minimal compositor + individual apps might be sufficient

---

### Multi-Container Workload Support
**Why:** Enable complex workloads (dev env + DB + cache, desktop + streaming)
- **Effort:** Large (1-2 weeks)
- **Value:** High (enables many use cases)
- **Interest:** Medium

**What it enables:**
- Dev environments: app + postgres + redis + mailhog
- Desktop streaming: compositor + desktop + sunshine
- Service stacks: app + metrics + logs
- Sidecars: any workload + helper containers

**Implementation:**
- Design pod TOML schema (`type = "pod"`, `[[pod.containers]]`)
- Update generator to create podman pods
- Update workload-ctl for pod operations (shell, exec, logs per container)
- Test and document

**Notes:**
**Decision:** Wait until actually blocked by specific use case (don't over-engineer)
**Status:** Not started

---

## High Interest (Want to do)

### LLM Inference Workloads
**Why:** It makes me sad to have unused fancy hardware
- **Effort:** Small (just workload configs)
- **Value:** High (utilize hardware)
- **Interest:** High

**Options:**
- Ollama (easiest, good API)
- llama.cpp (lightweight)
- text-generation-webui (feature-rich)
- vLLM (production serving)

**Notes:**
- **Config:** Straightforward - GPU passthrough to Tesla P40, host networking for API
- **Next action:** Create Ollama workload on Tesla P40 #1
- **Status:** Ready to start

---

### Dev Container Workloads
**Why:** Use big computer for remote development
- **Effort:** Small-Medium (per stack)
- **Value:** High (useful for actual work)
- **Interest:** High

**Stacks to create:**
- Node.js/TypeScript (single container)
- Python (single container)
- Rust (single container)
- Full-stack (needs multi-container: app + postgres + redis)

**Integration:** Could use with VSCode Remote-SSH or direct SSH
**Next action:** Create simple Node.js dev container
**Status:** Ready to start

---

## Medium Interest

### Home Assistant
**Why:** useful for home automation
- **Effort:** Small (1-2 days)
- **Value:** High
- **Interest:** Medium

**Value proposition:**
- User handles: Home automation logic, device integrations (Zigbee/Z-Wave/WiFi)
- We handle: Compute infrastructure (deployment, auto-restart, reliability, USB passthrough)
- User never thinks about: systemd, docker, networking, boot reliability

**Boundary:** Don't get into device management - stay in infrastructure lane

**Status:** Ready enough

---

### Standalone Workload System RPM
**Why:** Make workload system usable on any Fedora/RHEL, not just bootc
- **Effort:** Medium (RPM spec, testing on non-bootc systems)
- **Value:** Medium-High (enables broader adoption)
- **Interest:** Medium

**What gets packaged:**
- workload-ctl
- workload-generator
- workload-setup.py
- systemd integration files
- Documentation

**When:** After workload library proves value (have examples to show)
**Status:** Not started

---

### Containerize Base Image Services
**Why:** Smaller bootc base, modular updates, user choice
- **Effort:** Medium per service
- **Value:** Medium (optimization, not requirement)
- **Interest:** Low

**Services to consider:**
- Cockpit (complex - needs libvirt socket access for VM management)
- Prometheus node exporter (easy - good first candidate)
- Fail2ban (medium - needs firewall/log access)
- Borgbackup (easy - just mounts and schedule)
- Tailscale (medium - networking complexity)
- Monitoring tools → distrobox (btop, htop, inxi, etc.)

**Benefits of containerizing:**
- On immutable/bootc systems: Users can enable/disable without rebuilding image
- Smaller base image
- Independent service updates
- User choice (enable only what they need)

**Challenges:**
- Cockpit needs deep host integration (libvirt, D-Bus, system management)
- More complexity vs just including in base

**Decision:** Low priority - bootc immutability benefits exist but not urgent
**Status:** Not started

---

## Low Priority / Maybe Later

### Image Variants
**Why:** Users pick the right starting point for their use case
- **Effort:** Medium (CI/CD pipeline, Containerfile templates)
- **Value:** Medium (convenience for users)
- **Interest:** Low

**Potential variants:**
- hypervisor-minimal (core only, no extras)
- hypervisor-full (current - everything included)
- hypervisor-headless (no Cockpit/web tools)
- hypervisor-gpu-amd (optimized for AMD)
- hypervisor-gpu-nvidia (optimized for NVIDIA)
- home-automation-appliance (minimal + Home Assistant)

**When:** If there's external demand
**Status:** Not started

---

### Advanced Networking Features
**Current state:** Basic networking works (pasta, host, none, custom networks)

**Could add:**
- Automatic network creation (currently manual with `podman network create`)
- Network lifecycle management
- DNS configuration (custom servers, search domains)
- Network policies (firewall rules, traffic shaping)
- Multiple networks per container
- IPv6 support (untested)
- Network inspection tools

**Decision:** Wait until actually blocked
**Status:** Low priority

---

### Advanced Storage Features
**Current state:** Basic volume mounts work

**Could add:**
- Named volumes (podman volume management)
- Shared volumes (between multiple workloads)
- tmpfs mounts (in-memory filesystems)
- Bind mount options (more granular ro/rw/nosuid/noexec)
- Storage quotas (limit container storage size)
- Automatic cleanup (remove old images/volumes)
- Backup/restore (snapshot volume data)
- Volume drivers (different storage backends)
- Data migration tools

**Decision:** Wait until actually needed
**Status:** Medium priority

---

## Research/Validation Needed

### Headless Gaming Validation
**Question:** Can Steam run in container without physical display?
**Method:** Test with Cosy first (already validates GPU apps in containers)
**Display options:**
- Xvfb (virtual X11)
- Wayland headless backend (wlroots)
- Virtual GPU (DRM render node only)

**Blocks:** Gaming workload implementation
**Status:** Not tested yet

---

### Sunshine Streaming Integration
**Question:** Does Sunshine capture containerized apps properly?
**Test:** Run Sunshine alongside containerized Steam, verify capture works
**Considerations:**
- Same container vs separate containers (multi-container question)
- Does Sunshine need special access?
- Performance overhead?

**Blocks:** Gaming streaming setup
**Status:** Not tested yet

---

## Easy, High Value

Start here when unsure what to work on:

- [ ] **Pi-hole workload** (1 day, immediately useful)
- [ ] **Local container registry** (1 day, useful for dev)
- [ ] **Simple dev container** (1 day, one language stack)
- [ ] **Prometheus node exporter** (1 day, easy containerization example)

---

## Review Schedule

- **Created:** 2026-01-03
- **Last Review:** 2026-01-11
- **Next Review:** When picking next thing to work on

**Review process:**
1. Read through sections
2. Move ideas between sections as interest changes
3. Add new ideas to "Random Ideas"
4. Pick something
5. Update status as work progresses
6. Commit changes to git

## Random Ideas (Unsorted)

*Quick capture spot - organize into sections above during review*

- VPN killswitch for proxy workload (ensure traffic doesn't leak)
- Automatic backup of workload configs (git-based or scheduled)
- Web UI for workload management (Cockpit integration plugin?)
- Workload health monitoring with alerts (email/webhook on failures)
- Resource usage dashboard (Grafana + custom metrics)
- Automated testing of workload examples (CI that validates each config)
- Container image builder workload (dedicated build environment)
- CI/CD runner workload (GitLab/GitHub/Gitea runner)
- Game server workloads (Valheim, Factorio, etc.)
- Home automation appliance bootc variant (minimal + HA)
- Gaming-optimized image variant (tuned, low latency kernel)
- Workload templates/scaffolding (generate from template)
- Import docker-compose files to workload TOML (migration tool)
- Ansible integration for provisioning (manage workloads as code)
- Workload dependency management (start B after A)
- Secrets rotation automation (auto-rotate credentials periodically)
- Workload migration tools (move between hosts)
- Resource recommendations (suggest limits based on usage)
- Cost analysis (if running on cloud, estimate costs)

