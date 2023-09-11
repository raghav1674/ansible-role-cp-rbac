import unittest
from unittest.mock import patch, Mock

import cp_rbac


class TestCPMetadataApiRequest(unittest.TestCase):
    def setUp(self):
        self.domain = "https://localhost:8090"
        self.path = "metadataClusterId"
        self.username = "superUser"
        self.password = "superUser"
        self.verify_ssl = False
        self.cp_metadata_api_request = cp_rbac.CPMetadataApiRequest(self.domain, self.path, self.username, self.password, self.verify_ssl)

    def test_url(self):
        actual_domain = self.cp_metadata_api_request.url()
        expected_domain = "{}/{}/{}".format(self.domain, "security/1.0", self.path)
        self.assertEqual(actual_domain, expected_domain)

    def test_basic_params(self):
        actual_basic_auth = self.cp_metadata_api_request.basic_params()["auth"]
        self.assertEqual(actual_basic_auth.username, self.username)
        self.assertEqual(actual_basic_auth.password, self.password)

    @patch.multiple(cp_rbac.CPMetadataApiRequest, basic_params=Mock(return_value=dict()), url=Mock(return_value="http://localhost:8090"))
    @patch("cp_rbac.requests")
    def test_get_entity(self, mock_request):
        response_text = "kafka-cluster1"
        response_code = 200

        mock_response = Mock()
        mock_response.status_code = response_code
        mock_response.text = response_text
        mock_request.get.return_value = mock_response
        actual_response = self.cp_metadata_api_request.get_entity()

        self.assertEqual(actual_response.text, response_text)
        self.assertEqual(actual_response.status_code, response_code)

    @patch.multiple(cp_rbac.CPMetadataApiRequest, basic_params=Mock(return_value=dict()), url=Mock(return_value="http://localhost:8090"))
    @patch("cp_rbac.requests")
    def test_post_entity(self, mock_request):
        response_json = {"message": "RoleBinding Created"}
        response_code = 201

        mock_response = Mock()
        mock_response.status_code = response_code
        mock_response.json.return_value = response_json
        mock_request.post.return_value = mock_response
        actual_response = self.cp_metadata_api_request.post_entity({})

        self.assertEqual(actual_response.json(), response_json)
        self.assertEqual(actual_response.status_code, response_code)

    @patch.multiple(cp_rbac.CPMetadataApiRequest, basic_params=Mock(return_value=dict()), url=Mock(return_value="http://localhost:8090"))
    @patch("cp_rbac.requests")
    def test_put_entity(self, mock_request):
        response_json = {"message": "RoleBinding Updated"}
        response_code = 204

        mock_response = Mock()
        mock_response.status_code = response_code
        mock_response.json.return_value = response_json
        mock_request.put.return_value = mock_response
        actual_response = self.cp_metadata_api_request.put_entity({})

        self.assertEqual(actual_response.json(), response_json)
        self.assertEqual(actual_response.status_code, response_code)

    @patch.multiple(cp_rbac.CPMetadataApiRequest, basic_params=Mock(return_value=dict()), url=Mock(return_value="http://localhost:8090"))
    @patch("cp_rbac.requests")
    def test_delete_entity(self, mock_request):
        response_json = {"message": "RoleBinding Deleted"}
        response_code = 200

        mock_response = Mock()
        mock_response.status_code = response_code
        mock_response.json.return_value = response_json
        mock_request.delete.return_value = mock_response
        actual_response = self.cp_metadata_api_request.delete_entity({})

        self.assertEqual(actual_response.json(), response_json)
        self.assertEqual(actual_response.status_code, response_code)


class TestCPMetadataApiService(unittest.TestCase):
    def setUp(self):
        self.domain = "https://localhost:8090"
        self.path = "metadataClusterId"
        self.username = "superUser"
        self.password = "superUser"
        self.verify_ssl = False
        self.resource_role_bindings = [cp_rbac.ResourceRoleBinding("DeveloperRead", {"resourceType": "Group", "name": "test-*", "patternType": "LITERAL"}), cp_rbac.ResourceRoleBinding("DeveloperManage", {"resourceType": "Topic", "name": "test-*", "patternType": "LITERAL"})]
        self.cluster_role_bindings = [cp_rbac.ClusterRoleBinding("Operator"), cp_rbac.ClusterRoleBinding("UserAdmin")]
        self.mds_scope = cp_rbac.MetadataClusterScope("testKafkaCluster")
        self.principal = "User:testUser"

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_get_rolebindings_for_a_principal(self, mock_cpmetadata_api_request):
        response_json = {self.principal: {"Operator": [], "UserAdmin": [], "DeveloperRead": [{"resourceType": "Group", "name": "test-*", "patternType": "LITERAL"}], "DeveloperManage": [{"resourceType": "Topic", "name": "test-*", "patternType": "LITERAL"}]}}
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)
        resource_role_bindings, cluster_role_binding = cp_metadata_api_service._CPMetadataApiService__get_rolebindings_for_a_principal()

        self.assertListEqual(cp_metadata_api_service.cluster_role_bindings, cluster_role_binding)
        self.assertListEqual(cp_metadata_api_service.resource_role_bindings, resource_role_bindings)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_get_rolebindings_for_a_principal_with_empty_response(self, mock_cpmetadata_api_request):
        response_json = {}
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)
        resource_role_bindings, cluster_role_binding = cp_metadata_api_service._CPMetadataApiService__get_rolebindings_for_a_principal()

        self.assertListEqual([], cluster_role_binding)
        self.assertListEqual([], resource_role_bindings)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test__get_rolebindings_for_a_principal_with_exception(self, mock_cpmetadata_api_request):
        response_json = {"message": "Bad Request"}
        mock_response = Mock()
        mock_response.ok = False
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)

        with self.assertRaises(Exception) as e:
            cp_metadata_api_service._CPMetadataApiService__get_rolebindings_for_a_principal()
        self.assertEqual(str(e.exception), str(response_json))

    def test__group_role_binding_by(self):
        expected_result = {resource_role_binding.role_name: [resource_role_binding.binding] for resource_role_binding in self.resource_role_bindings}
        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)
        actual_result = cp_metadata_api_service._CPMetadataApiService__group_role_binding_by(self.resource_role_bindings, "role_name")

        self.assertEqual(actual_result, expected_result)

    def test__diff_bindings_with_resource_role_bindings(self):
        actual_bindings = [self.resource_role_bindings[0], self.resource_role_bindings[1]]
        requested_bindings = [self.resource_role_bindings[1]]
        expected_result = {"add": [], "remove": [self.resource_role_bindings[0]]}

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)
        actual_result = cp_metadata_api_service._CPMetadataApiService__diff_bindings(actual_bindings, requested_bindings)

        self.assertEqual(actual_result, expected_result)

    def test__diff_bindings_with_cluster_role_bindings(self):
        actual_bindings = [self.cluster_role_bindings[0]]
        requested_bindings = [self.cluster_role_bindings[0], self.cluster_role_bindings[1]]
        expected_result = {"add": [self.cluster_role_bindings[1]], "remove": []}

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)
        actual_result = cp_metadata_api_service._CPMetadataApiService__diff_bindings(actual_bindings, requested_bindings)

        self.assertEqual(actual_result, expected_result)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_compare_cluster_rolebindings(self, mock_cpmetadata_api_request):
        response_json = {self.principal: {"Operator": []}}

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)
        is_cluster_role_binding_equal, diff_cluster_bindings, actual_cluster_bindings, requested_cluster_binding = cp_metadata_api_service.compare_cluster_rolebindings()

        self.assertEqual(is_cluster_role_binding_equal, False)
        self.assertEqual(diff_cluster_bindings, {"add": [self.cluster_role_bindings[1]], "remove": []})
        self.assertListEqual(actual_cluster_bindings, [self.cluster_role_bindings[0]])
        self.assertListEqual(requested_cluster_binding, self.cluster_role_bindings)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_compare_resource_rolebindings(self, mock_cpmetadata_api_request):
        response_json = {self.principal: {"DeveloperRead": [{"resourceType": "Group", "name": "test-*", "patternType": "LITERAL"}]}}
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)
        is_resource_role_binding_equal, diff_resource_bindings, actual_resource_bindings, requested_resource_binding = cp_metadata_api_service.compare_resource_rolebindings()

        self.assertEqual(is_resource_role_binding_equal, False)
        self.assertEqual(diff_resource_bindings, {"add": [self.resource_role_bindings[1]], "remove": []})
        self.assertListEqual(actual_resource_bindings, [self.resource_role_bindings[0]])
        self.assertListEqual(requested_resource_binding, self.resource_role_bindings)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_create_cluster_role_bindings(self, mock_cpmetadata_api_request):
        response_json = {"message": "Cluster Role Binding Created"}
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)
        result = cp_metadata_api_service.create_cluster_role_bindings(self.cluster_role_bindings)

        self.assertEqual(None, result)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_create_cluster_role_bindings_with_exception(self, mock_cpmetadata_api_request):
        response_json = {"message": "Invalid Cluster Scope"}
        mock_response = Mock()
        mock_response.ok = False
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)

        with self.assertRaises(Exception) as e:
            cp_metadata_api_service.create_cluster_role_bindings(self.cluster_role_bindings)
        self.assertEqual(str(e.exception), str(response_json))

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_delete_cluster_role_bindings(self, mock_cpmetadata_api_request):
        response_json = {"message": "Cluster Role Binding Deleted"}
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.delete_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)
        result = cp_metadata_api_service.delete_cluster_role_bindings(self.cluster_role_bindings)

        self.assertEqual(None, result)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_delete_cluster_role_bindings_with_exception(self, mock_cpmetadata_api_request):
        response_json = {"message": "Invalid Cluster Scope"}
        mock_response = Mock()
        mock_response.ok = False
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.delete_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.cluster_role_bindings, self.verify_ssl)

        with self.assertRaises(Exception) as e:
            cp_metadata_api_service.delete_cluster_role_bindings(self.cluster_role_bindings)
        self.assertEqual(str(e.exception), str(response_json))

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_create_resource_role_bindings(self, mock_cpmetadata_api_request):
        response_json = {"message": "Resource Role Binding Created"}
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.resource_role_bindings, self.verify_ssl)
        result = cp_metadata_api_service.create_resource_role_bindings(self.resource_role_bindings)

        self.assertEqual(None, result)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_create_resource_role_bindings_with_exception(self, mock_cpmetadata_api_request):
        response_json = {"message": "Invalid Cluster Scope"}
        mock_response = Mock()
        mock_response.ok = False
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.resource_role_bindings, self.verify_ssl)

        with self.assertRaises(Exception) as e:
            cp_metadata_api_service.create_resource_role_bindings(self.resource_role_bindings)
        self.assertEqual(str(e.exception), str(response_json))

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_delete_resource_role_bindings(self, mock_cpmetadata_api_request):
        response_json = {"message": "Resource Role Binding Deleted"}
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.delete_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.resource_role_bindings, self.verify_ssl)
        result = cp_metadata_api_service.delete_resource_role_bindings(self.resource_role_bindings)

        self.assertEqual(None, result)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_delete_resource_role_bindings_with_exception(self, mock_cpmetadata_api_request):
        response_json = {"message": "Invalid Cluster Scope"}
        mock_response = Mock()
        mock_response.ok = False
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.delete_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.resource_role_bindings, self.verify_ssl)

        with self.assertRaises(Exception) as e:
            cp_metadata_api_service.delete_resource_role_bindings(self.resource_role_bindings)
        self.assertEqual(str(e.exception), str(response_json))

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_update_role_bindings(self, mock_cpmetadata_api_request):
        response_json = {"message": "Sample Role Binding"}
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.delete_entity.return_value = mock_response
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.resource_role_bindings, self.verify_ssl)

        result = cp_metadata_api_service.update_role_bindings({"add": self.cluster_role_bindings, "remove": []}, {"add": [], "remove": self.resource_role_bindings})

        self.assertEqual(None, result)

    @patch("cp_rbac.CPMetadataApiRequest")
    def test_update_role_bindings_with_exception(self, mock_cpmetadata_api_request):
        response_json = {"message": "Invalid Cluster Scope"}
        mock_response = Mock()
        mock_response.ok = False
        mock_response.json.return_value = response_json
        mock_cpmetadata_api_request_instance = mock_cpmetadata_api_request.return_value
        mock_cpmetadata_api_request_instance.delete_entity.return_value = mock_response
        mock_cpmetadata_api_request_instance.post_entity.return_value = mock_response

        cp_metadata_api_service = cp_rbac.CPMetadataApiService(self.domain, self.username, self.password, self.mds_scope, self.principal, self.resource_role_bindings, self.resource_role_bindings, self.verify_ssl)

        with self.assertRaises(Exception) as e:
            cp_metadata_api_service.update_role_bindings({"add": self.cluster_role_bindings, "remove": []}, {"add": [], "remove": self.resource_role_bindings})
        self.assertEqual(str(e.exception), str(response_json))
