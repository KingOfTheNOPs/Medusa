from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import base64, hashlib, pathlib, re, struct


def _normalize_typed_args(value):
    if not value:
        return []
    result = []
    for entry in value:
        if isinstance(entry, dict):
            kind = entry.get("type")
            item = entry.get("value")
        elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
            kind, item = entry[0], entry[1]
        elif isinstance(entry, str) and ":" in entry:
            kind, item = entry.split(":", 1)
        else:
            raise ValueError("BOF arguments must use type:value entries")
        kind = str(kind).lower()
        if kind not in ("int16", "int32", "string", "wchar", "base64"):
            raise ValueError("unsupported BOF argument type: {}".format(kind))
        result.append((kind, item))
    return result


def _pack_args(value):
    packed = bytearray()
    for kind, item in _normalize_typed_args(value):
        if kind == "int16":
            packed += struct.pack("<h", int(item))
        elif kind == "int32":
            packed += struct.pack("<i", int(item))
        elif kind == "string":
            raw = str(item).encode("utf-8") + b"\x00"
            packed += struct.pack("<I", len(raw)) + raw
        elif kind == "wchar":
            raw = str(item).encode("utf-16le") + b"\x00\x00"
            packed += struct.pack("<I", len(raw)) + raw
        else:
            raw = base64.b64decode(str(item), validate=True)
            packed += struct.pack("<I", len(raw)) + raw
        if len(packed) > 2 * 1024 * 1024 - 4:
            raise ValueError("packed BOF arguments exceed 2 MiB")
    return struct.pack("<I", len(packed)) + packed


class ExecuteCoffArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="coff_name", type=ParameterType.ChooseOne, dynamic_query_function=self.get_files,
                description="COFF previously loaded with register_coff",
                parameter_group_info=[ParameterGroupInfo(required=True, group_name="Registered", ui_position=1)],
            ),
            CommandParameter(
                name="bof_file", type=ParameterType.File, description="One-shot x64 COFF/BOF",
                parameter_group_info=[ParameterGroupInfo(required=True, group_name="New", ui_position=1)],
            ),
            CommandParameter(
                name="function_name", type=ParameterType.String, default_value="go", description="BOF entrypoint",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Registered", ui_position=2),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=2),
                ],
            ),
            CommandParameter(
                name="coff_arguments", type=ParameterType.TypedArray, default_value=[],
                choices=["int16", "int32", "string", "wchar", "base64"],
                description="Apollo-style typed BOF arguments: int32:1 string:host",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, group_name="Registered", ui_position=3),
                    ParameterGroupInfo(required=False, group_name="New", ui_position=3),
                ],
            ),
        ]

    async def get_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        response = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        files = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback, LimitByCallback=False, Filename=""
        ))
        if not files.Success:
            response.Error = files.Error
            return response
        response.Success = True
        response.Choices = sorted(set(f.Filename for f in files.Files if f.Filename.lower().endswith((".o", ".obj", ".bof", ".coff"))))
        return response

    async def parse_arguments(self):
        if not self.command_line or self.command_line[0] != "{":
            raise ValueError("Use the execute_coff tasking modal")
        self.load_args_from_json_string(self.command_line)

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class ExecuteCoffCommand(CommandBase):
    cmd = "execute_coff"
    needs_admin = False
    help_cmd = "execute_coff (select x64 BOF and optional arguments)"
    description = "Execute an AMD64 Beacon Object File with strict validation and W^X protections"
    version = 2
    author = "Medusa COFFLoader integration"
    attackmapping = ["T1106", "T1620"]
    argument_class = ExecuteCoffArguments
    attributes = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        group = taskData.args.get_parameter_group_name()
        function_name = taskData.args.get_arg("function_name") or "go"
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", function_name):
            return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=False, Error="invalid BOF entrypoint")
        group_info = [ParameterGroupInfo(required=True, group_name=group)]
        packed = _pack_args(taskData.args.get_arg("coff_arguments"))
        taskData.args.remove_arg("coff_arguments")
        taskData.args.add_arg("packed_arguments", base64.b64encode(packed).decode("ascii"), parameter_group_info=group_info)

        helper_path = pathlib.Path(self.agent_code_path).parent / "native" / "coffloader" / "coffloader.x64.dll"
        helper = helper_path.read_bytes()
        helper_response = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
            TaskID=taskData.Task.ID,
            FileContents=helper,
            Filename="coffloader.x64.dll",
            Comment="Integrity-pinned Medusa in-memory COFF loader",
            DeleteAfterFetch=True,
        ))
        if not helper_response.Success:
            return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=False, Error=helper_response.Error)
        taskData.args.add_arg("loader_file", helper_response.AgentFileId, parameter_group_info=group_info)
        taskData.args.add_arg("loader_sha256", hashlib.sha256(helper).hexdigest(), parameter_group_info=group_info)

        if group == "Registered":
            name = taskData.args.get_arg("coff_name")
        else:
            file_response = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID, AgentFileID=taskData.args.get_arg("bof_file")
            ))
            name = file_response.Files[0].Filename if file_response.Success and file_response.Files else "uploaded BOF"
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True, DisplayParams="{}!{}".format(name, function_name))

    async def process_response(self, task, response):
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
