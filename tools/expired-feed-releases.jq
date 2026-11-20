# Release creation timestamps can tie when several feeds point to one commit.
[.[][] | select(.draft == false and .prerelease == false)
       | .tag_name | select(test("^data-feeds-(0|[1-9][0-9]*)$"))] as $tags
| if ($tags | index($current)) == null then
    error("verified feed missing from published releases")
  else
    $tags | map(select(. != $current))
    | sort_by([length, .]) | reverse | .[2:][]
  end
