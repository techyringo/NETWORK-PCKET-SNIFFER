#! /usr/bin/env python

import pandas as pd, networkx as nx, matplotlib.pyplot as plt
from networkx.algorithms import bipartite
import json

# Build lists of nodes and edges:

df = (pd.read_csv('tst.csv'))
B = nx.Graph()
B.add_nodes_from(df['Destination'], bipartite=0)
B.add_nodes_from(df['Source'], bipartite=1)
B.add_weighted_edges_from(
    [( row['Source'], row['Destination'],1) for idx, row in df.iterrows()], 
    weight='weight')

print(B.edges(data=True))
# [('test1', 'example.org', {'weight': 1}), ('test3', 'example.org', {'weight': 1}), ('test2', 'example.org', {'weight': 1}), ('website.com', 'else', {'weight': 1}), ('site.com', 'something', {'weight': 1})]

pos = {node:[0, i] for i,node in enumerate(df['Source'])}
pos.update({node:[1, i] for i,node in enumerate(df['Destination'])})
nx.draw(B, pos, with_labels=False)
for p in pos:  # raise text positions
    pos[p][1] += 0.25
nx.draw_networkx_labels(B, pos)
all_nodes = list(B.nodes())


print(B.edges())

nodes = [{'name': str(i)}
            for i in B.nodes()]
links = [{'source': u[0], 'target': u[1]}
            for u in B.edges()]
with open('graph.json', 'w') as f:
    json.dump({'links': links}, f, indent=4,)
pos=nx.spring_layout(pos),
with_labels = True,
plt.show()

