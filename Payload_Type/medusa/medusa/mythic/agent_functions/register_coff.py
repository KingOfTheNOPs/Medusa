from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import pathlib, re


class RegisterCoffArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="bof_file", type=ParameterType.File, description="AMD64 COFF/BOF to retain in agent memory"),
            CommandParameter(name="coff_name", type=ParameterType.String, default_value="", description="Optional cache name"),
        ]

    async def parse_arguments(self):
        if not self.command_line or self.command_line[0] != "{":
            raise ValueError("Use the register_coff tasking modal")
        self.load_args_from_json_string(self.command_line)

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class RegisterCoffCommand(CommandBase):
    cmd = "register_coff"
    needs_admin = False
    help_cmd = "register_coff (select an x64 BOF)"
    description = "Load a BOF into an in-memory agent cache for later execute_coff tasking"
    version = 1
    author = "Medusa COFFLoader integration"
    argument_class = RegisterCoffArguments
    attributes = CommandAttributes(supported_python_versions=["Python 3.8"], supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        result = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID, AgentFileID=taskData.args.get_arg("bof_file")
        ))
        if not result.Success or not result.Files:
            return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=False, Error="uploaded BOF was not found")
        name = taskData.args.get_arg("coff_name") or result.Files[0].Filename
        name = pathlib.PurePath(name).name
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
            return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=False, Error="invalid COFF cache name")
        taskData.args.add_arg("coff_name", name)
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True, DisplayParams=name)

    async def process_response(self, task, response):
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
