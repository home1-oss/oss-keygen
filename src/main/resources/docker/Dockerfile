
FROM ${docker.registry}/java:oracle-8u101-jdk-alpine














ADD entrypoint.sh /root/
RUN chmod 755 /root/*.sh
ADD	*-exec.jar /root/
RUN touch /root/*-exec.jar


USER root
WORKDIR /root/
ENTRYPOINT ["/root/entrypoint.sh"]
CMD []
