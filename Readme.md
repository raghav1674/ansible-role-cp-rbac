#### Ansible Role for Confluent Platform Metadata RBAC

##### To get started:

`git clone https://github.com/raghav1674/ansible-role-cp-rbac.git`

`cd ansible-role-cp-rbac`

##### Create Virtual Environment for development

`python3 -m pip install virtualenv`

`python3 -m virtualenv cp-rbac-env`

`source cp-rbac-env/bin/activate`

`python3 -m pip install -r requirements.txt`


##### Run Ansible Code:

- Setup the Confluent Kafka Platform using [cp-demo](https://github.com/confluentinc/cp-demo)

- Make sure the virtual environment is activated

`cd ansible-role-cp-rbac`

`ansible-playbook playbook.yml --diff --check`

##### Run tests:

`source cp-rbac-env/bin/activate`

`cd roles/cp-rbac/library`

`python3 -m coverage run  -m unittest test_cp_rbac.py -v`

`python3 -m coverage report cp_rbac.py`

`python3 -m coverage html cp_rbac.py`

##### Format and Lint

`python3 -m black --config black.toml --check roles/cp-rbac/library/`

`python3 -m black --config black.toml roles/cp-rbac/library/`

`python3 -m flake8 --config  .flake8 roles/cp-rbac/library/`

##### Deactivate Virtualenv

`deactivate`


##### NOTE:

- Required packages on the managed nodes are:
    - python3
    - python3-requests

- If you want to use custom CA cert, please make sure either the CA is already trusted in the managed node or provide the file path (absolute file path as it is present in managed node not in the control node) in `verifySsl` argument.
