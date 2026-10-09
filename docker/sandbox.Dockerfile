FROM python:3.11-slim@sha256:bab1b7ef4b450c81002278d035eff85ebe394ae94df904f7a3ba14f7e16e487b

# Application code, credentials and Docker's socket never enter this image.
# Pin the built image ID/digest in SANDBOX_IMAGE for controlled deployments.
COPY sandbox-requirements.txt /tmp/sandbox-requirements.txt
RUN pip install --no-cache-dir -r /tmp/sandbox-requirements.txt && rm /tmp/sandbox-requirements.txt
RUN mkdir -p /workspace && chmod 1777 /workspace
USER 65534:65534
WORKDIR /workspace
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1 MPLBACKEND=Agg MPLCONFIGDIR=/tmp/matplotlib
