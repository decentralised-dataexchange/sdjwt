FROM jupyter/base-notebook:python-3.10

USER root

RUN apt-get update --yes
RUN apt-get install gcc --yes

# Install Poetry
RUN pip install --no-cache-dir poetry

# Switch back to the jovyan user
USER jovyan

# Copy and install project dependencies
COPY pyproject.toml poetry.lock /home/jovyan/work/
WORKDIR /home/jovyan/work

RUN poetry config virtualenvs.create false && poetry install --no-root --no-interaction --no-ansi

# Start Jupyter Notebook
CMD ["start-notebook.sh", "--NotebookApp.token=''"]