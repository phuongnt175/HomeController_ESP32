Run with IDF 5.1.2:
1. idf.py set-target esp32c3
2. idf.py menuconfig
3. in menuconfig go to component config --> ESP HTTPS SERVER --> Enable ESP_HTTPS_SERVER component
4. save menuconfig and then build: idf.py build
5. upload firmware: idf.py flash or idf.py flash monitor
