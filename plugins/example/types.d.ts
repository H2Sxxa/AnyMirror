/// <reference path="../types/plugin.d.ts" />

type ExampleConfig = {
  origin_hosts?: string[];
  mirror_url?: string;
  control_header?: string;
  response_header?: string;
};

type ExampleState = {
  origin_hosts: string[];
  mirror_url: string;
  control_header: string;
  response_header: string;
};

type ExampleProgram = {
  origin_hosts: string[];
  mirror_url: string;
  control_header: string;
  response_header: string;
  rules: PluginCompiledRule[];
};
