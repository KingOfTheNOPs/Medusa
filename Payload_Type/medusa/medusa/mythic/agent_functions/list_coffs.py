from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ListCoffsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ListCoffsCommand(CommandBase):
    cmd = "list_coffs"
    needs_admin = False
    help_cmd = "list_coffs"
    description = "List COFF objects retained in the agent's in-memory cache"
    version = 1
    author = "Medusa COFFLoader integration"
    argument_class = ListCoffsArguments
    browser_script = BrowserScript(script_name="list_coffs", author="Medusa COFFLoader integration", for_new_ui=True)
    attributes = CommandAttributes(supported_python_versions=["Python 3.8"], supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData):
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task, response):
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
