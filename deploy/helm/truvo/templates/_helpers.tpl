{{- define "truvo.image" -}}
{{ .root.Values.global.image.registry }}/{{ .name }}:{{ .root.Values.global.image.tag }}
{{- end -}}

{{- define "truvo.commonEnv" -}}
- name: TRUVO_VAULT_ADDR
  value: {{ .Values.config.vaultAddr | quote }}
- name: TRUVO_KAFKA_BOOTSTRAP
  value: {{ .Values.config.kafkaBootstrap | quote }}
- name: TRUVO_SCHEMA_REGISTRY
  value: {{ .Values.config.schemaRegistry | quote }}
- name: TRUVO_OBJSTORE_ENDPOINT
  value: {{ .Values.config.objstoreEndpoint | quote }}
- name: TRUVO_SVCAUTH
  value: {{ .Values.config.svcauth | quote }}
{{- end -}}
