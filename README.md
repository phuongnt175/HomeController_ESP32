Run with IDF 5.1.2:

### Step 1: set target

```bash
idf.py set-target esp32c3
```

### Step 2: menuconfig

```bash
idf.py menuconfig
```

In menuconfig go to component config --> ESP HTTPS SERVER --> Enable ESP_HTTPS_SERVER component.
Remember save menuconfig.

### Step 3: Flash and launch monitor
Flash the program and launch IDF Monitor:

```bash
idf.py flash monitor
```
