import json
import logging
import re
import requests

ACTION_TABLE_URL = 'https://raw.githubusercontent.com/salesforce/policy_sentry/master/policy_sentry/shared/data/iam-definition.json'
ACTIONS_NOT_COVERED_BY_ACCESS_ADVISOR = ['iam:PassRole', 's3:GetObject', 's3:PutObject']

action_map = requests.get(ACTION_TABLE_URL, timeout=60).json(timeout=60)


class PolicyAnalyzer:
    @staticmethod
    def convert_to_list(list_or_single_object):
        """Converts a single object or a list of objects into a list.
        Parameters:
            - list_or_single_object (object or list): The object or list of objects to be converted into a list.
        Returns:
            - list: A list containing the object or objects from the input.
        Processing Logic:
            - Checks if the input is a list.
            - If it is a list, returns the input.
            - If it is not a list, converts the input into a list and returns it.
        Example:
            convert_to_list(5) # Returns [5]
            convert_to_list([1, 2, 3]) # Returns [1, 2, 3]"""
        
        if isinstance(list_or_single_object, list):
            return list_or_single_object
        return [list_or_single_object]

    @staticmethod
    def _get_policy_actions(policy_document: dict):
        """Get the list of actions from a policy document.
        Parameters:
            - policy_document (dict): The policy document to be analyzed.
        Returns:
            - actions_list (list): A list of actions defined in the policy document.
        Processing Logic:
            - Convert policy document to list.
            - Check if statement is an Allow statement.
            - If statement has Action defined, add to actions_list.
            - If statement has no Action defined, log warning.
            - Return list of actions.
        Example:
            policy_document = {
                'Statement': {
                    'Effect': 'Allow',
                    'Action': 's3:GetObject'
                }
            }
            _get_policy_actions(policy_document)
            # Output: ['s3:GetObject']"""
        
        policy_statements = PolicyAnalyzer.convert_to_list(policy_document['Statement'])
        actions_list = []
        for statement in policy_statements:
            if statement['Effect'] == 'Allow':
                if statement.get('Action'):
                    actions_list.extend(PolicyAnalyzer.convert_to_list(statement['Action']))
                else:
                    logging.warning('The following statement is an Allow statement with no Actions defined, which is '
                                    'considered bad practice as it might allow implicit permissions')
                    logging.warning(json.dumps(statement))
        return actions_list

    @staticmethod
    def is_policy_unused(policy_document: dict, services_last_accessed: list) -> bool:
        """Checks if a policy document is unused by comparing it to a list of services that have been recently accessed.
        Parameters:
            - policy_document (dict): A dictionary containing the policy document to be checked.
            - services_last_accessed (list): A list of services that have been recently accessed.
        Returns:
            - bool: True if the policy document is unused, False otherwise.
        Processing Logic:
            - Checks if the policy document contains a "Deny" effect or a "NotAction" effect.
            - Checks if the policy document contains any actions that are not covered by Access Advisor.
            - Compares the services accessed through the policy to the list of recently accessed services.
            - Returns True if the policy document is unused, False otherwise."""
        
        statements_str = json.dumps(policy_document['Statement'])
        if '"Effect": "Deny"' in statements_str or '"NotAction":' in statements_str:
            # If statement contains a "Deny" effect - Access Advisor won't detect that action because it is a restriction
            # If statement contains a "NotAction" effect - Access Advisor won't detect usage of this policy correctly
            return False

        policy_actions = PolicyAnalyzer._get_policy_actions(policy_document)
        if len([action for action in policy_actions if
                len(list(filter(re.compile(action.replace('*', '.*')).match, ACTIONS_NOT_COVERED_BY_ACCESS_ADVISOR))) > 0]) > 0:
            return False

        services_accessed_through_policy = list(set(map(lambda action: action.split(':')[0], policy_actions)))
        return len(
            [service for service in services_accessed_through_policy if
             len(list(filter(re.compile(service.replace('*', '.*')).match, services_last_accessed))) > 0
             ]) == 0

    @staticmethod
    def policy_is_write_access(policy_document):
        """Checks if the given policy document allows write access.
        Parameters:
            - policy_document (dict): A dictionary containing the policy document to be analyzed.
        Returns:
            - bool: True if the policy document allows write access, False otherwise.
        Processing Logic:
            - Get all actions from the policy document.
            - Check if any action is a wildcard or contains a wildcard.
            - Split the action into service and name.
            - Replace wildcard with regex and get all matching privileges.
            - Check if any privilege has write access.
            - Return True if any action has write access, False otherwise."""
        
        actions = PolicyAnalyzer._get_policy_actions(policy_document)
        for action in actions:
            if action == '*' or '*' in action.split(':'):
                return True
            [action_service, action_name] = action.split(':')
            try:
                action_regex = action_name.replace('*', '.*')
                action_objs = []
                for priv, priv_obj in action_map.get(action_service, {}).get('privileges', []).items():
                    if re.match(action_regex, priv):
                        action_objs.append(priv_obj)
            except StopIteration:
                action_objs = []
                logging.warning(f'The action {action} is not in the actions map!')
                logging.debug(f'action_map = {action_map}')

            for action_obj in action_objs:
                if action_obj['access_level'] in ['Write', 'Delete', 'Permissions management']:
                    return True
        return False
