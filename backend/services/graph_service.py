from collections import deque, defaultdict
from typing import List, Dict, Tuple, Set, Any

class GraphService:
    @classmethod
    def analyze_dependency_graph(
        cls, 
        packages: List[Dict[str, Any]], 
        edges: List[Tuple[str, str]], 
        repo_name: str
    ) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]]]:
        """
        Analyzes the dependency graph.
        - Identifies the root node.
        - Calculates depth for all packages (shortest path from root).
        - Marks if packages are direct (depth == 1) or transitive (depth > 1).
        - Computes dependents count (how many nodes depend on a package).
        Returns:
            Tuple of (updated packages list with depth/is_direct/dependents_count, clean edges list)
        """
        if not packages:
            return [], []

        # Create adjacency lists
        adj = defaultdict(list)
        in_degree = defaultdict(int)
        all_nodes = {p["name"] for p in packages}

        for parent, child in edges:
            adj[parent].append(child)
            in_degree[child] += 1

        # Identify Root Node
        # Root is a node with 0 in-degree.
        # If there are multiple or none, check if one matches the repo_name or has name like "app",
        # otherwise pick the one with highest out-degree, or default to the first node with 0 in-degree.
        root = None
        zeros = [node for node in all_nodes if in_degree[node] == 0]
        
        # Try finding a matches
        for z in zeros:
            if z.lower() in (repo_name.lower(), "app", "root", "document"):
                root = z
                break
        
        if not root:
            if zeros:
                # Default to the node with the most outgoing dependencies among the zeros
                root = max(zeros, key=lambda x: len(adj[x]))
            else:
                # Cyclic or no 0-in-degree nodes, choose the one with the highest out-degree
                root = max(all_nodes, key=lambda x: len(adj[x])) if all_nodes else None

        # Calculate Depths and Shortest Paths using BFS
        depths = {}
        paths = {}
        if root:
            queue = deque([(root, 0, [root])])
            depths[root] = 0
            paths[root] = [root]
            
            while queue:
                curr, d, path = queue.popleft()
                for neighbor in adj[curr]:
                    if neighbor not in depths:
                        depths[neighbor] = d + 1
                        paths[neighbor] = path + [neighbor]
                        queue.append((neighbor, d + 1, path + [neighbor]))

        # Calculate Dependents count (size of reachable ancestors)
        # We can construct the reversed graph and run a DFS/BFS from each node to count how many nodes can reach it.
        rev_adj = defaultdict(list)
        for parent, children in adj.items():
            for child in children:
                rev_adj[child].append(parent)

        dependents_counts = {}
        for node in all_nodes:
            # BFS on reversed graph to find all ancestors
            visited = set()
            q = deque([node])
            visited.add(node)
            while q:
                curr = q.popleft()
                for parent in rev_adj[curr]:
                    if parent not in visited:
                        visited.add(parent)
                        q.append(parent)
            # Dependents count is ancestors minus the node itself
            dependents_counts[node] = len(visited) - 1

        # Update package metadata
        updated_packages = []
        for pkg in packages:
            name = pkg["name"]
            depth = depths.get(name, 99)  # default high depth if unreachable
            
            # Save depth and direct/transitive indicators
            pkg_copy = pkg.copy()
            pkg_copy["depth"] = depth
            pkg_copy["is_direct"] = (depth == 1)
            pkg_copy["dependents_count"] = dependents_counts.get(name, 0)
            pkg_copy["path_from_root"] = paths.get(name, [name])
            
            # Topological properties for ML model
            pkg_copy["in_degree"] = in_degree[name]
            pkg_copy["out_degree"] = len(adj[name])
            
            updated_packages.append(pkg_copy)

        return updated_packages, edges
