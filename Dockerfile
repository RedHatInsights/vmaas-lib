# Build vmaas app with local changes to vmaas-lib
FROM registry.access.redhat.com/ubi9/ubi-minimal

# install postgresql from centos if not building on RHSM system
RUN FULL_RHEL=$(microdnf repolist --enabled | grep rhel-8) ; \
    if [ -z "$FULL_RHEL" ] ; then \
        rpm -Uvh https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/Packages/centos-stream-repos-9.0-18.el9.noarch.rpm \
                 https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/Packages/centos-gpg-keys-9.0-18.el9.noarch.rpm && \
        sed -i 's/^\(enabled.*\)/\1\npriority=200/;' /etc/yum.repos.d/centos*.repo ; \
    fi

ARG RPMS="python3 python3-pip python3-rpm which rsync rpm-devel git shadow-utils diffutils systemd libicu postgresql go-toolset"
ARG VAR_RPMS=""
RUN for x in ${RPMS}; do microdnf -y install --setopt=install_weak_deps=0 --setopt=tsflags=nodocs $x; done
RUN for x in ${VAR_RPMS}; do microdnf -y install --setopt=install_weak_deps=0 --setopt=tsflags=nodocs $x; done
RUN microdnf clean all

RUN git clone https://github.com/RedHatInsights/vmaas.git --branch master /vmaas

WORKDIR /vmaas

ENV LC_ALL=C.utf8
ENV LANG=C.utf8
ARG PIPENV_CHECK=1
ARG PIPENV_PYUP_API_KEY=""
ARG VAR_PIPENV_INSTALL_OPT=""
RUN pip3 install --upgrade pipenv==2022.12.19 && \
    pipenv install --ignore-pipfile --deploy --system $VAR_PIPENV_INSTALL_OPT && \
    if [ "${PIPENV_CHECK}" == 1 ] ; then pipenv check --system; fi

RUN mv /vmaas/vmaas/reposcan/rsyncd.conf   /etc/ 

RUN install -m 1777 -d /data && \
    adduser --gid 0 -d /vmaas --no-create-home vmaas
RUN mkdir -p /vmaas/go/src/vmaas && chown -R vmaas:root /vmaas/go
RUN mv /vmaas/vmaas-go/* /vmaas/go/src/vmaas

ENV PYTHONPATH=/vmaas
ENV GOPATH=/vmaas/go \
    PATH=$PATH:/vmaas/go/bin

RUN mkdir /vmaas-lib && chown -R vmaas:root /vmaas-lib

ADD go.* /vmaas-lib/
ADD /vmaas/ /vmaas-lib/vmaas/

WORKDIR /vmaas/go/src/vmaas
RUN go mod edit -replace github.com/redhatinsights/vmaas-lib=/vmaas-lib
RUN go mod tidy
RUN go mod download
RUN go build -v main.go

WORKDIR /vmaas

USER vmaas
