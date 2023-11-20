## Setup

Get Neo4j running:
```
docker run --name pmapper --env=NEO4J_AUTH=none --publish=7474:7474 --publish=7687:7687 --volume=$HOME/neo4j/data:/data neo4j:4.4
```

## Cypher Queries

Priv Esc Paths:

```cypher
MATCH path = (start)-[*1..3]->(end {is_admin: true})
WHERE start.is_admin = false
and not start.arn ends with 'AWSServiceRoleForSSO'
RETURN path
```

Cross-Account Access:
```cypher
MATCH path = (start:Principal)-[link:CROSS_ACCOUNT_ACCESS]->(middle:Principal) //-[*0..3]->(end:Principal {is_admin: true})
RETURN start, link, middle
```

External Account Access:
```cypher
MATCH path = (start)-[link:EXTERNAL_ACCESS]->(end)//-[*0..3]->(end:Principal {is_admin: true})
RETURN start, link, end
```

External Account Access to Admin:
```cypher
MATCH path = (start)-[:EXTERNAL_ACCESS]->(mid)-[:EDGE|CROSS_ACCOUNT_ACCESS*0..]->(end {is_admin: true})
RETURN path
```