from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class UnregisterCoffArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [CommandParameter(name="coff_name", type=ParameterType.String, description="Cached COFF name")]

    async def parse_arguments(self):
        if self.command_line and self.command_line[0] == "{": self.load_args_from_json_string(self.command_line)
        else: self.add_arg("coff_name", self.command_line)


class UnregisterCoffCommand(CommandBase):
    cmd = "unregister_coff"
    needs_admin = False
    help_cmd = "unregister_coff name.o"
    description = "Zero and remove an object from the in-memory COFF cache"
    version = 1
    author = "Medusa COFFLoader integration"
    supported_ui_features = ["medusa:unregister_coff"]
    argument_class = UnregisterCoffArguments
    attributes = CommandAttributes(supported_python_versions=["Python 3.8"], supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData):
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True, DisplayParams=taskData.args.get_arg("coff_name"))

    async def process_response(self, task, response):
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
