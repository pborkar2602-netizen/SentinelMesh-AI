# SentinelMesh v3 Screenshot Verification Suite

**Generated**: 2026-11-14
**Target URL**: `http://localhost:3000`
**Viewports Covered**: 1366x768 (Desktop Standard) and 1920x1080 (Full HD)

## Screenshot Index

| Filename | Description | Resolution |
|---|---|---|
| `docs/screenshots/1366x768_01_hero_home.png` | Hero & Aurora Mesh (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_02_live_demo_enforce.png` | Live Demo Enforce Mode — 0 records exposed (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_03_live_demo_monitor.png` | Live Demo Monitor Mode — 45 records exposed (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_04_radar_evidence.png` | 5-Axis Defense Radar & Evidence Dashboard (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_tour_step_1.png` | Guided Tour Step 1 / 9 (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_tour_step_2.png` | Guided Tour Step 2 / 9 (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_tour_step_3.png` | Guided Tour Step 3 / 9 (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_tour_step_4.png` | Guided Tour Step 4 / 9 (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_tour_step_5.png` | Guided Tour Step 5 / 9 (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_tour_step_6.png` | Guided Tour Step 6 / 9 (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_tour_step_7.png` | Guided Tour Step 7 / 9 (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_tour_step_8.png` | Guided Tour Step 8 / 9 (1366x768) | 1366x768 |
| `docs/screenshots/1366x768_tour_step_9.png` | Guided Tour Step 9 / 9 (1366x768) | 1366x768 |
| `docs/screenshots/1920x1080_01_hero_home.png` | Hero & Aurora Mesh (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_02_live_demo_enforce.png` | Live Demo Enforce Mode — 0 records exposed (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_03_live_demo_monitor.png` | Live Demo Monitor Mode — 45 records exposed (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_04_radar_evidence.png` | 5-Axis Defense Radar & Evidence Dashboard (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_tour_step_1.png` | Guided Tour Step 1 / 9 (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_tour_step_2.png` | Guided Tour Step 2 / 9 (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_tour_step_3.png` | Guided Tour Step 3 / 9 (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_tour_step_4.png` | Guided Tour Step 4 / 9 (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_tour_step_5.png` | Guided Tour Step 5 / 9 (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_tour_step_6.png` | Guided Tour Step 6 / 9 (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_tour_step_7.png` | Guided Tour Step 7 / 9 (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_tour_step_8.png` | Guided Tour Step 8 / 9 (1920x1080) | 1920x1080 |
| `docs/screenshots/1920x1080_tour_step_9.png` | Guided Tour Step 9 / 9 (1920x1080) | 1920x1080 |


## Viewport Boundary Clamping Verification
Every guided tour step was verified via Playwright bounding-box assertions (`assert top >= 0 and bottom <= viewport_height`). Card popup positioning is dynamically measured and unconditionally clamped so headers, body text, and action buttons are never clipped across any screen resolution.
