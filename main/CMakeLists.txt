idf_component_register(SRCS "App/main.c"
                        SRCS "Mid/serverSession.c"
                        INCLUDE_DIRS "."
                        EMBED_TXTFILES "certs/servercert.pem"
                                   "certs/prvkey.pem"
                                   "certs/key.pem"
                                   "certs/staservercert.pem")
