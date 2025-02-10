# Build vmaas app with local changes to vmaas-lib
FROM registry.access.redhat.com/ubi8/ubi-minimal

ARG VAR_RPMS=""
RUN curl -o /etc/yum.repos.d/postgresql.repo \
        https://copr.fedorainfracloud.org/coprs/g/insights/postgresql-16/repo/epel-8/group_insights-postgresql-16-epel-8.repo

RUN microdnf module enable nginx:1.20 || :
RUN microdnf module disable postgresql || :
RUN microdnf install -y --setopt=install_weak_deps=0 --setopt=tsflags=nodocs \
        python312 python3.12-pip python3-rpm python3-dnf which nginx rpm-devel git-core shadow-utils diffutils systemd libicu postgresql go-toolset \
        $VAR_RPMS && \
        ln -s /usr/lib64/python3.6/site-packages/rpm /usr/lib64/python3.12/site-packages/rpm && \
    microdnf clean all

RUN git clone https://github.com/RedHatInsights/vmaas.git --branch master /vmaas

WORKDIR /vmaas

ENV LC_ALL=C.utf8
ENV LANG=C.utf8
ARG VAR_POETRY_INSTALL_OPT="--only main"
RUN pip3.12 install --upgrade pip && \
    pip3.12 install --upgrade poetry~=2.0 poetry-plugin-export
RUN poetry export $VAR_POETRY_INSTALL_OPT -f requirements.txt --output requirements.txt && \
    pip3.12 install -r requirements.txt

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
