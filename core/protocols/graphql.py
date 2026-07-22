# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from typing import List, Dict, Optional

import requests


class GraphQLTester:
    """Tests GraphQL endpoints for security issues."""

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind ofType { name } }
          }
        }
      }
    }
    """

    def __init__(self, session: requests.Session):
        self.session = session

    def detect_endpoint(self, url: str) -> bool:
        """Check if a URL has a GraphQL endpoint."""
        common_paths = ["/graphql", "/gql", "/query", "/v1/graphql", "/api/graphql"]
        for path in common_paths:
            test_url = url.rstrip("/") + path
            try:
                resp = self.session.post(
                    test_url,
                    json={"query": "{__typename}"},
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                if resp.ok and "data" in resp.text:
                    return True
            except Exception:
                continue
        return False

    def introspect(self, endpoint: str) -> Optional[Dict]:
        """Run GraphQL introspection query."""
        try:
            resp = self.session.post(
                endpoint,
                json={"query": self.INTROSPECTION_QUERY},
                timeout=15,
            )
            if resp.ok:
                data = resp.json()
                if "data" in data and data["data"].get("__schema"):
                    return data["data"]
            return None
        except Exception:
            return None

    def test_batch(self, endpoint: str) -> List[Dict]:
        """Test for GraphQL batching attack."""
        results = []
        batch = [
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
        ]
        try:
            resp = self.session.post(endpoint, json=batch, timeout=10)
            if resp.ok and isinstance(resp.json(), list):
                results.append({
                    "type": "batch_attack",
                    "detail": "GraphQL accepts batched queries (potential DoS)",
                    "confidence": "Medium",
                })
        except Exception:
            pass
        return results

    def test_depth(self, endpoint: str) -> List[Dict]:
        """Test for deep query complexity."""
        depth_payload = "{__typename"
        for i in range(20):
            depth_payload += "{__typename"
        depth_payload += "}" * 21

        try:
            resp = self.session.post(endpoint, json={"query": depth_payload}, timeout=15)
            if resp.ok:
                results = [{
                    "type": "deep_query",
                    "detail": "GraphQL accepts deep nested queries (potential DoS)",
                    "confidence": "High",
                }]
                return results
        except Exception:
            pass
        return []
