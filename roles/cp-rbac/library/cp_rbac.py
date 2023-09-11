#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import requests
import json


PRINCIPAL_TYPES = ["Group", "User"]


class MetadataClusterScope:
    """
    MetadataClusterScope Representation
    """

    def __init__(self, mds_cluster_id, cluster_type=None, cluster_id=None):
        self.mds_cluster_id = mds_cluster_id
        self.cluster_type = cluster_type
        self.cluster_id = cluster_id

    def __repr__(self):
        return str(self.get_request_body())

    def get_request_body(self):
        mds_scope_request = {"clusters": {"kafka-cluster": self.mds_cluster_id}}

        if self.cluster_type is None:
            return mds_scope_request

        mds_scope_request["clusters"].update({self.cluster_type: self.cluster_id})
        return mds_scope_request


class ResourceRoleBinding:
    """
    ResourceRoleBinding Representation
    """

    def __init__(self, role_name, binding):
        self.binding = binding
        self.role_name = role_name

    def __repr__(self):
        return "{}: {}".format(self.role_name, self.binding)

    def __eq__(self, other):
        return self.binding == other.binding and self.role_name == other.role_name


class ClusterRoleBinding:
    """
    ClusterRoleBinding Representation
    """

    def __init__(self, role_name):
        self.role_name = role_name

    def __repr__(self):
        return "{}".format(self.role_name)

    def __eq__(self, other):
        return self.role_name == other.role_name


class CPMetadataApiRequest:
    """
    Confluent Platform Metadata Api Request
    """

    def __init__(self, domain, path, username, password, verify_ssl):
        self.domain = domain
        self.path = path
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

    def get_entity(self):
        url = self.url()
        params = self.basic_params()
        result = requests.get(url, verify=self.verify_ssl, **params)
        return result

    def post_entity(self, data):
        url = self.url()
        params = self.basic_params()
        headers = {"Content-Type": "application/json"}
        params["headers"] = headers
        result = requests.post(url, data, verify=self.verify_ssl, **params)
        return result

    def put_entity(self, data):
        url = self.url()
        params = self.basic_params()
        headers = {"Content-Type": "application/json"}
        params["headers"] = headers
        result = requests.put(url, data, verify=self.verify_ssl, **params)
        return result

    def delete_entity(self, data):
        url = self.url()
        params = self.basic_params()
        headers = {"Content-Type": "application/json"}
        params["headers"] = headers
        result = requests.delete(url, data=data, verify=self.verify_ssl, **params)
        return result

    def url(self):
        domain = self.domain[:-1] if self.domain.endswith("/") else self.domain
        return "{}/{}/{}".format(domain, "security/1.0", self.path)

    def basic_params(self):
        params = dict()
        params["auth"] = requests.auth.HTTPBasicAuth(self.username, self.password)
        return params


class CPMetadataApiService:
    """
    Confluent Platform Metadata Api Service
    """

    def __init__(self, domain, username, password, mds_scope, principal, resource_role_bindings, cluster_role_bindings, state, verify_ssl):
        self.domain = domain
        self.resource_role_bindings = resource_role_bindings
        self.cluster_role_bindings = cluster_role_bindings
        self.mds_scope = mds_scope
        self.principal = principal
        self.username = username
        self.password = password
        self.state = state
        self.verify_ssl = verify_ssl

    def cpmetadata_api_request(self, path):
        return CPMetadataApiRequest(self.domain, path, self.username, self.password, self.verify_ssl)

    def compare_resource_rolebindings(self):
        """
        Compares the difference between the actual resource role binding and the requested resource role binding
        """
        resource_role_bindings, _ = self.__get_rolebindings_for_a_principal()
        requested_resource_role_bindings = self.resource_role_bindings
        diff_resource_role_bindings = self.__diff_bindings(resource_role_bindings, requested_resource_role_bindings)
        return True if len(diff_resource_role_bindings["add"]) == 0 and len(diff_resource_role_bindings["remove"]) == 0 else False, diff_resource_role_bindings, resource_role_bindings, requested_resource_role_bindings

    def compare_cluster_rolebindings(self):
        """
        Compares the difference between the actual cluster role binding and the requested cluster role binding
        """
        _, cluster_role_bindings = self.__get_rolebindings_for_a_principal()
        requested_cluster_role_bindings = self.cluster_role_bindings
        diff_cluster_role_bindings = self.__diff_bindings(cluster_role_bindings, requested_cluster_role_bindings)
        return True if len(diff_cluster_role_bindings["add"]) == 0 and len(diff_cluster_role_bindings["remove"]) == 0 else False, diff_cluster_role_bindings, cluster_role_bindings, requested_cluster_role_bindings

    def create_cluster_role_bindings(self, cluster_roles):
        """
        Create the cluster role bindings
        """
        path = "principals/{}/roles/{}"
        request_body = self.mds_scope.get_request_body()
        for role in cluster_roles:
            response = self.cpmetadata_api_request(path.format(self.principal, role.role_name)).post_entity(json.dumps(request_body))
            if not response.ok:
                raise Exception(str(response.json()))

    def delete_cluster_role_bindings(self, cluster_roles):
        """
        Delete the cluster role bindings
        """
        path = "principals/{}/roles/{}"
        request_body = self.mds_scope.get_request_body()
        for role in cluster_roles:
            response = self.cpmetadata_api_request(path.format(self.principal, role.role_name)).delete_entity(json.dumps(request_body))
            if not response.ok:
                raise Exception(str(response.json()))

    def create_resource_role_bindings(self, role_bindings):
        """
        Create Resource Role Bindings
        """
        resource_role_bindings_by_role_name = self.__group_role_binding_by(role_bindings, "role_name")
        path = "principals/{}/roles/{}/bindings"
        for role_name in resource_role_bindings_by_role_name:
            request_body = {"scope": self.mds_scope.get_request_body(), "resourcePatterns": resource_role_bindings_by_role_name[role_name]}
            response = self.cpmetadata_api_request(path.format(self.principal, role_name)).post_entity(json.dumps(request_body))
            if not response.ok:
                raise Exception(str(response.json()))

    def delete_resource_role_bindings(self, role_bindings):
        """
        Delete Resource Role Bindings
        """
        resource_role_bindings_by_role_name = self.__group_role_binding_by(role_bindings, "role_name")
        path = "principals/{}/roles/{}/bindings"

        for role_name in resource_role_bindings_by_role_name:
            request_body = {"scope": self.mds_scope.get_request_body(), "resourcePatterns": resource_role_bindings_by_role_name[role_name]}
            response = self.cpmetadata_api_request(path.format(self.principal, role_name)).delete_entity(json.dumps(request_body))
            if not response.ok:
                raise Exception(str(response.json()))

    def update_role_bindings(self, diff_cluster_role_bindings, diff_resource_role_bindings):
        """
        Wrapper Update method to create and delete role bindings
        """

        self.create_resource_role_bindings(diff_resource_role_bindings["add"])
        self.delete_resource_role_bindings(diff_resource_role_bindings["remove"])

        self.create_cluster_role_bindings(diff_cluster_role_bindings["add"])
        self.delete_cluster_role_bindings(diff_cluster_role_bindings["remove"])

    def __get_rolebindings_for_a_principal(self):
        """
        Returns the cluster role binding & resource role bindings for a given principal
        """
        path = "lookup/principal/{}/resources".format(self.principal)
        response = self.cpmetadata_api_request(path).post_entity(json.dumps(self.mds_scope.get_request_body()))

        if response.ok:
            response_data = response.json()

            if len(response_data) == 0:
                return [], []

            resource_role_bindings = list()
            cluster_role_bindings = list()

            for role_name, bindings in response_data[self.principal].items():
                if len(bindings) == 0:
                    cluster_role_bindings.append(ClusterRoleBinding(role_name))
                for binding in bindings:
                    resource_role_bindings.append(ResourceRoleBinding(role_name, binding))
            return resource_role_bindings, cluster_role_bindings
        else:
            raise Exception(str(response.json()))

    @staticmethod
    def __group_role_binding_by(role_bindings, field):
        """
        Group the list of resource role_binding object based on a given field
        """
        role_bindings_by_field = {}
        for role_binding in role_bindings:
            field_name = role_binding.__dict__[field]
            binding = role_binding.binding
            if field_name not in role_bindings_by_field:
                role_bindings_by_field[field_name] = list()
            role_bindings_by_field[field_name].append(binding)
        return role_bindings_by_field

    @staticmethod
    def __diff_bindings(actual, requested):
        """
        Returns the difference between the actual role binding with the requested role binding
        """
        diff_bindings = {"add": [], "remove": []}
        for binding in requested:
            found = False
            for actual_binding in actual:
                if binding == actual_binding:
                    found = True
                    break
            if not found:
                diff_bindings["add"].append(binding)

        for binding in actual:
            found = False
            for requested_binding in requested:
                if binding == requested_binding:
                    found = True
                    break
            if not found:
                diff_bindings["remove"].append(binding)
        return diff_bindings


def main():
    fields = dict(
        domain=dict(required=True, type="str"),
        username=dict(required=True, type="str"),
        password=dict(required=True, type="str", no_log=True),
        principal_type=dict(required=True, type="str", choices=["group", "user"]),
        data=dict(required=False, type="dict"),
        cluster_type=dict(required=True, type="str"),
        cluster_id=dict(required=True, type="str"),
        mds_cluster_id=dict(required=True, type="str"),
        state=dict(required=False, type="str", default="present", choices=["absent", "present"]),
        verify_ssl=dict(required=False, type="bool", default=True),
    )

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    domain = module.params["domain"]
    username = module.params["username"]
    password = module.params["password"]
    data = module.params["data"]
    cluster_type = module.params["cluster_type"]
    cluster_id = module.params["cluster_id"]
    mds_cluster_id = module.params["mds_cluster_id"]
    state = module.params["state"]
    principal_type = module.params["principal_type"]
    verify_ssl = module.params["verify_ssl"]

    # mds scope object
    try:
        mds_response = CPMetadataApiRequest(domain, "metadataClusterId", username, password, verify_ssl).get_entity()
        if not mds_response.ok:
            module.fail_json(msg=f"{mds_response.reason}")
    except Exception as e:
        module.fail_json(msg=str(e))

    current_mds_cluster_id = mds_response.text

    assert mds_cluster_id == current_mds_cluster_id, f"Provided mds_cluster id is different from the current mds id {mds_cluster_id} != {current_mds_cluster_id}"

    mds_scope = MetadataClusterScope(mds_cluster_id=mds_cluster_id)

    if cluster_type != "kafka-cluster":
        mds_scope.cluster_type = cluster_type
        mds_scope.cluster_id = cluster_id

    # creating a list of rolebinding objects
    resource_role_bindings = list()
    cluster_role_bindings = list()

    for cluster_role_binding in data.get("clusterRoleBindings", {}):
        role_name = cluster_role_binding["roleName"]
        cluster_role_bindings.append(ClusterRoleBinding(role_name))

    for role_binding in data.get("resourceRoleBindings", {}):
        role_name = role_binding["roleName"]
        binding = role_binding
        del binding["roleName"]
        resource_role_bindings.append(ResourceRoleBinding(role_name, binding))

    assert isinstance(principal_type, str)

    principal_type = principal_type.title()
    principal_name = data.get("principal", None)

    assert principal_type in PRINCIPAL_TYPES and isinstance(principal_name, str) and len(principal_name) > 0

    principal = "{}:{}".format(principal_type, principal_name)

    cpmetadata_api_service = CPMetadataApiService(domain=domain, username=username, password=password, mds_scope=mds_scope, resource_role_bindings=resource_role_bindings, cluster_role_bindings=cluster_role_bindings, principal=principal, state=state, verify_ssl=verify_ssl)

    def should_update(module):
        is_resource_role_binding_equal, diff_resource_bindings, actual_resource_bindings, requested_resource_binding = cpmetadata_api_service.compare_resource_rolebindings()
        is_cluster_role_binding_equal, diff_cluster_bindings, actual_cluster_bindings, requested_cluster_binding = cpmetadata_api_service.compare_cluster_rolebindings()

        if not (is_cluster_role_binding_equal and is_resource_role_binding_equal):
            if not module.check_mode:
                cpmetadata_api_service.update_role_bindings(diff_cluster_bindings, diff_resource_bindings)
            if module._diff:
                module.exit_json(changed=True, diff={"before": json.dumps({"resource_bindings": str(actual_resource_bindings), "cluster_bindings": str(actual_cluster_bindings)}, indent=2) + "\n", "after": json.dumps({"resource_bindings": str(requested_resource_binding), "cluster_bindings": str(requested_cluster_binding)}, indent=2) + "\n"})
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    try:
        should_update(module)
    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
