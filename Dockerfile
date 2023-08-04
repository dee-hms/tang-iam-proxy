FROM registry-proxy.engineering.redhat.com/rh-osbs/ubi9-minimal:9.2-717

ENV SUMMARY="Tang IAM proxy" \
    DESCRIPTION="Tang IAM proxy allows to redirect traffic to tang backend by SPIFFE ID" \
    VERSION=0.1 \
    PORT=8000

LABEL name="rhel9/tang-iam-proxy" \
      summary="${SUMMARY}" \
      description="${DESCRIPTION}" \
      version="${VERSION}" \
      usage="podman run -d -p 8000:8000 -v database-dir:/var/db --name tang rhel9/tang-iam-proxy" \
      maintainer="Red Hat, Inc." \
      help="cat /README.md" \
      com.redhat.component="tang-iam-proxy" \
      io.k8s.display-name="Tang IAM Proxy" \
      io.k8s.description="${DESCRIPTION}" \
      io.openshift.expose-services="8000:tang-iam-proxy" \
      io.openshift.tags="tang-iam-proxy,container,NBDE,PBD,clevis,LUKS,McCallum-Relyea,Network Bound Disk Encryption"


RUN microdnf update -y && \
    microdnf install -y \
        psmisc \
        procps-ng && \
    microdnf clean all && \
    rm -rf /var/cache/yum

COPY root /

VOLUME ["/var/db"]
EXPOSE ${PORT}

CMD ["/usr/bin/tang-iam-proxy"]
