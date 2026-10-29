// A literal lookup binds its named group. A group-list projection or computed
// lookup may consume any group. Keep claim/subject changes in the native app
// door, including when a mapping is activated during a membership transaction.
export const mappedGroup = `EXISTS(
 SELECT 1 FROM auth_groups bound_group,
 auth_apps mapped_app JOIN auth_mapping_versions mapping ON mapping.app_id=mapped_app.id AND mapping.version=mapped_app.mapping_version,
 json_tree(mapping.program) node
 WHERE bound_group.id=? AND mapped_app.disabled_at IS NULL
 AND CASE node.type WHEN 'object' THEN (
  json_extract(node.value,'$.groups')=1 OR
  (json_extract(node.value,'$.op')='inGroup' AND
   (json_type(node.value,'$.args[0]')<>'text' OR json_extract(node.value,'$.args[0]')=bound_group.name))
 ) ELSE 0 END
)`
