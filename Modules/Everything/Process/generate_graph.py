import argparse
import ast
import networkx as nx
import matplotlib.pyplot as plt
from UtilityController import UtilityTools

def get_project_id_by_name(name, all_current_nodes):
    for node in all_current_nodes:
        if node['name'] == name:
            project_id = node.get('project_id')
            display_name = node.get('display_name')
            project_id = project_id if project_id not in [None, 'N/A'] else None
            display_name = display_name if display_name not in [None, 'N/A'] else None
            return project_id, display_name
    return None, None

def get_all_unique_node_names(session, show_deleted=False):
    if show_deleted:
        data = session.get_data("abstract-tree-hierarchy", columns=["name", "display_name", "project_id", "state"])
    else:
        data = session.get_data("abstract-tree-hierarchy", columns=["name", "display_name", "project_id", "state"], conditions="state == 1")
    return data

def run_module(user_args, session, first_run=False, last_run=False, output_format = ["table"]):
    parser = argparse.ArgumentParser(description="Generate MatPlotLib Graph", allow_abbrev=False)
    parser.add_argument("-v", "--debug", action="store_true")
    parser.add_argument("--show-deleted", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args(user_args)

    debug = args.debug
    project_id = session.project_id
    all_current_nodes = get_all_unique_node_names(session, show_deleted=args.show_deleted)

    ancestor_list = []
    for node in all_current_nodes:
        name = node["name"]
        if "organizations/" != name:
            ancestors = session.get_immediate_ancestor(name)
            if ancestors:
                ancestor_list.extend(ancestors)

    unique_relationships = set(map(str, ancestor_list))
    unique_relationships = [tuple(ast.literal_eval(relationship)) for relationship in unique_relationships]
    filtered_relationships = [rel for rel in unique_relationships if rel != ('Uknown', None, None) and rel != ('Unknown', None, None)]

    level_nodes = {}
    more_relations = True
    while more_relations:
        more_relations = False
        for node, _, destination in filtered_relationships:
            if destination == 'None' or destination == '':
                if node not in level_nodes:
                    more_relations = True
                    level_nodes[node] = 1
            else:
                if destination in level_nodes:
                    if node not in level_nodes:
                        more_relations = True
                        level_nodes[node] = level_nodes[destination] + 1

    G = nx.DiGraph()
    for source, node_type, destination in filtered_relationships:
        if destination != 'None' and source != 'None' and destination != '':
            G.add_edge(source, destination)
        G.add_node(source, type=node_type, subset=level_nodes[source])

    node_colors = {
        'org': 'black',
        'folder': 'black',
        'project': 'black'
    }

    label_colors = {
        'org': (1.0, 0.8, 0.4),
        'folder': (0.8, 0.8, 0.8),
        'project': (0.4, 1.0, 0.4)
    }

    node_types = nx.get_node_attributes(G, 'type')
    node_color_list = [node_colors[node_types[node]] for node in G.nodes]

    pos = nx.multipartite_layout(G, subset_key="subset")
    plt.figure(figsize=(24, 36))  # Adjust the figure size for the new layout

    # Adjust the positions to rotate the layout 90 degrees to the right
    pos = {k: (v[1], -v[0]) for k, v in pos.items()}

    nx.draw(G, pos, with_labels=False, node_shape='s', edge_color='gray', arrows=True, width=2, node_color=node_color_list)

    labels = {}
    font_size = 10

    for node in G.nodes:
        project_id, common_name = get_project_id_by_name(node, all_current_nodes)
        node_data = next(item for item in all_current_nodes if item["name"] == node)
        state = int(node_data["state"])
        state_mapping = {
            0: "STATE_UNSPECIFIED",
            1: "ACTIVE",
            2: "DELETE_REQUESTED"
        }
        state_label = state_mapping.get(state, "UNKNOWN_STATE")

        if project_id: G.nodes[node]['project_id'] = project_id
        if common_name: G.nodes[node]['common_name'] = common_name
        label = f"{node}"
        if project_id:
            label += f"\nproject_id: {project_id}"
        if common_name:
            label += f"\ncommon_name: {common_name}"
        if args.show_deleted:
            label += f"\nstate: {state_label}"

        labels[node] = label

    for node, (x, y) in pos.items():
        plt.text(x, y, labels[node], ha='center', va='center', fontsize=font_size,
                 bbox=dict(facecolor=label_colors[node_types[node]], edgecolor='black', boxstyle='round,pad=0.3'))

    plt.scatter([], [], color=(1.0, 0.8, 0.4), edgecolor='black', label='org')
    plt.scatter([], [], color=(0.8, 0.8, 0.8), edgecolor='black', label='folder')
    plt.scatter([], [], color=(0.4, 1.0, 0.4), edgecolor='black', label='project')

    plt.legend(loc='upper left')

    if args.output:
        plt.savefig(args.output, format="svg", dpi=300)  # Save as high-resolution SVG
    else:
        import time
        file_path = UtilityTools.get_save_filepath(session.workspace_directory_name, f"GraphSnapshot_{time.time()}.svg", "Reports Graphs")
        plt.savefig(file_path, format="svg", dpi=300)  # Save as high-resolution SVG

    plt.title('Projects/Folders/Orgs Graph')
    plt.show(block=False)
