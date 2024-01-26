idf_component_register(SRCS "App/main.c"
                        SRCS "Mid/http_session.c"
                        INCLUDE_DIRS "."
                        EMBED_TXTFILES "certs/servercert.pem"
                                   "certs/prvkey.pem")
