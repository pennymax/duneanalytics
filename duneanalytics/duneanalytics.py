# -*- coding: utf-8 -*- #
"""This provides the DuneAnalytics class implementation"""

from requests import Session
import logging

# --------- Constants --------- #

BASE_URL = "https://dune.com"
GRAPH_URL = 'https://core-hsr.dune.com/v1/graphql'
GRAPH_URL_NEW = 'https://app-api.dune.com/v1/graphql'

# --------- Constants --------- #
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s : %(levelname)s : %(funcName)-9s : %(message)s'
)
logger = logging.getLogger("dune")


class DuneAnalytics:
    """
    DuneAnalytics class to act as python client for duneanalytics.com.
    All requests to be made through this class.
    """

    def __init__(self, username, password):
        """
        Initialize the object
        :param username: username for duneanalytics.com
        :param password: password for duneanalytics.com
        """
        self.csrf = None
        self.auth_refresh = None
        self.token = None
        self.username = username
        self.password = password
        self.query_id = None
        self.session = Session()
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,'
                      'image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'dnt': '1',
            'sec-ch-ua': '"Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'origin': BASE_URL,
            'upgrade-insecure-requests': '1'
        }
        self.session.headers.update(headers)

    def login(self):
        """
        Try to login to duneanalytics.com & get the token
        :return:
        """
        login_url = BASE_URL + '/auth/login'
        csrf_url = BASE_URL + '/api/auth/csrf'
        auth_url = BASE_URL + '/api/auth'

        # fetch login page
        self.session.get(login_url)

        # get csrf token
        self.session.post(csrf_url)
        self.csrf = self.session.cookies.get('csrf')

        # try to login
        form_data = {
            'action': 'login',
            'username': self.username,
            'password': self.password,
            'csrf': self.csrf,
            'next': BASE_URL
        }

        self.session.post(auth_url, data=form_data)
        self.auth_refresh = self.session.cookies.get('auth-refresh')
        if self.auth_refresh is None:
            logger.warning("Login Failed!")

    def fetch_auth_token(self):
        """
        Fetch authorization token for the user
        :return:
        """
        session_url = BASE_URL + '/api/auth/session'

        response = self.session.post(session_url)
        if response.status_code == 200:
            self.token = response.json().get('token')
            if self.token is None:
                logger.warning("Fetching Token Failed!")
        else:
            logger.error(response.text)

    def query_result_id(self, query_id):
        """
        Fetch the query result id for a query

        :param query_id: provide the query_id
        :return:
        """
        query_data = {"operationName": "GetResult", "variables": {"query_id": query_id},
                      "query": "query GetResult($query_id: Int!, $parameters: [Parameter!]) "
                               "{\n  get_result_v2(query_id: $query_id, parameters: $parameters) "
                               "{\n    job_id\n    result_id\n    error_id\n    __typename\n  }\n}\n"
                      }

        self.session.headers.update({'authorization': f'Bearer {self.token}'})

        response = self.session.post(GRAPH_URL, json=query_data)
        if response.status_code == 200:
            data = response.json()
            logger.debug(data)
            if 'errors' in data:
                logger.error(data.get('errors'))
                return None
            result_id = data.get('data').get('get_result_v2').get('result_id')
            return result_id
        else:
            logger.error(response.text)
            return None

    def query_result_id_v3(self, query_id):
        """
        Fetch the query result id for a query

        :param query_id: provide the query_id
        :return:
        """
        self.query_id = query_id
        query_data = {"operationName": "GetResult", "variables": {"query_id": query_id, "parameters": []},
                      "query": "query GetResult($query_id: Int!, $parameters: [Parameter!]!) "
                               "{\n  get_result_v3(query_id: $query_id, parameters: $parameters) "
                               "{\n    job_id\n    result_id\n    error_id\n    __typename\n  }\n}\n"
                      }

        self.session.headers.update({'authorization': f'Bearer {self.token}'})

        response = self.session.post(GRAPH_URL, json=query_data)
        if response.status_code == 200:
            data = response.json()
            logger.debug(data)
            if 'errors' in data:
                logger.error(data.get('errors'))
                return None
            result_id = data.get('data').get('get_result_v3').get('result_id')
            return result_id
        else:
            logger.error(response.text)
            return None
    
    def query_sql_code(self, query_id):
        """
        Fetch the query result id for a query

        :param query_id: provide the query_id
        :return:
        """
        self.query_id = query_id
        query_data = {"operationName": "FindQuery", 
                      "variables": {"favs_last_24h":False,"favs_last_7d":False,"favs_last_30d":False,"favs_all_time":True,"session_filter":{"_eq":122164},"id":query_id},
                      "query": """
                        query FindQuery($session_filter: Int_comparison_exp!, $id: Int!, $favs_last_24h: Boolean! = false, $favs_last_7d: Boolean! = false, $favs_last_30d: Boolean! = false, $favs_all_time: Boolean! = true) {
                        queries(where: {id: {_eq: $id}}) {
                            ...Query
                            favorite_queries(where: {user_id: $session_filter}, limit: 1) {
                            created_at
                            __typename
                            }
                            __typename
                        }
                        }

                        fragment Query on queries {
                        ...BaseQuery
                        ...QueryVisualizations
                        ...QueryForked
                        ...QueryUsers
                        ...QueryTeams
                        ...QueryFavorites
                        __typename
                        }

                        fragment BaseQuery on queries {
                        id
                        dataset_id
                        name
                        description
                        query
                        is_private
                        is_temp
                        is_archived
                        created_at
                        updated_at
                        schedule
                        tags
                        parameters
                        __typename
                        }

                        fragment QueryVisualizations on queries {
                        visualizations {
                            id
                            type
                            name
                            options
                            created_at
                            __typename
                        }
                        __typename
                        }

                        fragment QueryForked on queries {
                        forked_query {
                            id
                            name
                            user {
                            name
                            __typename
                            }
                            team {
                            handle
                            __typename
                            }
                            __typename
                        }
                        __typename
                        }

                        fragment QueryUsers on queries {
                        user {
                            ...User
                            __typename
                        }
                        team {
                            id
                            name
                            handle
                            profile_image_url
                            __typename
                        }
                        __typename
                        }

                        fragment User on users {
                        id
                        name
                        profile_image_url
                        __typename
                        }

                        fragment QueryTeams on queries {
                        team {
                            ...Team
                            __typename
                        }
                        __typename
                        }

                        fragment Team on teams {
                        id
                        name
                        handle
                        profile_image_url
                        __typename
                        }

                        fragment QueryFavorites on queries {
                        query_favorite_count_all @include(if: $favs_all_time) {
                            favorite_count
                            __typename
                        }
                        query_favorite_count_last_24h @include(if: $favs_last_24h) {
                            favorite_count
                            __typename
                        }
                        query_favorite_count_last_7d @include(if: $favs_last_7d) {
                            favorite_count
                            __typename
                        }
                        query_favorite_count_last_30d @include(if: $favs_last_30d) {
                            favorite_count
                            __typename
                        }
                        __typename
                        }

                      """
                      }

        self.session.headers.update({'authorization': f'Bearer {self.token}'})

        response = self.session.post(GRAPH_URL, json=query_data)
        if response.status_code == 200:
            data = response.json()
            logger.debug(data)
            if 'errors' in data:
                logger.error(data.get('errors'))
                return None
            # print(data)
            # result_id = data.get('data').get('get_result_v3').get('result_id')
            sql_codes = data.get('data').get('queries')[0]['query']
            return sql_codes
        else:
            logger.error(response.text)
            return None

    def query_result(self, result_id):
        """
        Fetch the result for a query
        :param result_id: result id of the query
        :return:
        """
        query_data = {"operationName": "FindResultDataByResult",
                      "variables": {"result_id": result_id, "error_id": "00000000-0000-0000-0000-000000000000"},
                      "query": "query FindResultDataByResult($result_id: uuid!, $error_id: uuid!) "
                               "{\n  query_results(where: {id: {_eq: $result_id}}) "
                               "{\n    id\n    job_id\n    runtime\n    generated_at\n    columns\n    __typename\n  }"
                               "\n  query_errors(where: {id: {_eq: $error_id}}) {\n    id\n    job_id\n    runtime\n"
                               "    message\n    metadata\n    type\n    generated_at\n    __typename\n  }\n"
                               "\n  get_result_by_result_id(args: {want_result_id: $result_id}) {\n    data\n    __typename\n  }\n}\n"
                      }

        self.session.headers.update({'authorization': f'Bearer {self.token}'})

        response = self.session.post(GRAPH_URL, json=query_data)
        if response.status_code == 200:
            data = response.json()
            logger.debug(data)
            return data
        else:
            logger.error(response.text)
            return {}

    def get_execution_result(self, execution_id):
        query_data = {"operationName": "GetExecution",
                      "variables": {"execution_id": execution_id, "query_id": self.query_id, "parameters": []},
                      "query": "query GetExecution($execution_id: String!, $query_id: Int!, $parameters: [Parameter!]!)"
                               " {\n  get_execution(\n    execution_id: $execution_id\n    query_id: $query_id\n    "
                               "parameters: $parameters\n  ) {\n    execution_queued {\n      execution_id\n      "
                               "execution_user_id\n      position\n      execution_type\n      created_at\n      "
                               "__typename\n    }\n    execution_running {\n      execution_id\n      "
                               "execution_user_id\n      execution_type\n      started_at\n      created_at\n      "
                               "__typename\n    }\n    execution_succeeded {\n      execution_id\n      "
                               "runtime_seconds\n      generated_at\n      columns\n      data\n      __typename\n    }"
                               "\n    execution_failed {\n      execution_id\n      type\n      message\n      metadata"
                               " {\n        line\n        column\n        hint\n        __typename\n      }\n      "
                               "runtime_seconds\n      generated_at\n      __typename\n    }\n    __typename\n  }\n}\n"}
        self.session.headers.update({'authorization': f'Bearer {self.token}'})

        response = self.session.post(GRAPH_URL_NEW, json=query_data)
        if response.status_code == 200:
            data = response.json()
            logger.debug(data)
            return data
        else:
            logger.error(response.text)
            return {}
