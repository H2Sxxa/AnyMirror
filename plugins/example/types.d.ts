/// <reference path="../types/plugin.d.ts" />

type ExampleConfig = {
  host?: string;
  mirror_url?: string;
  control_header?: string;
  response_header?: string;
};

type ExampleState = {
  host: string;
  mirror_url: string;
  control_header: string;
  response_header: string;
};

type ExampleProgram = {
  control_header: string;
  response_header: string;
  rules: PluginCompiledRule[];
};
