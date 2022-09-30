#!/bin/bash

. /usr/local/dynamic-resources/dynamic_resources.sh

function configure() {
  expand_catalina_opts
}

function expand_catalina_opts() {

    # CIS Tomcat9
    SAFR_OPTS_APPEND="-Dorg.apache.catalina.STRICT_SERVLET_COMPLIANCE=true -Dorg.apache.catalina.connector.RECYCLE_FACADES=true -Dorg.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH=false -Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=false"

    #XXX: we should probably deprecate CATALINA_OPTS_APPEND in favor of
    #     JAVA_OPTS_APPED, which is consistent with the rest of our images.
    CATALINA_OPTS="$CATALINA_OPTS $CATALINA_OPTS_APPEND $SAFR_OPTS_APPEND $(/opt/jolokia/jolokia-opts) $(/opt/jboss/container/prometheus/jws-prometheus-opts)"

    CATALINA_OPTS="$(adjust_java_options ${CATALINA_OPTS})"

    export CATALINA_OPTS
}
