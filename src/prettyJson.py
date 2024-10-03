from fastapi.responses import JSONResponse
import json


class PrettyJSONResponse(JSONResponse):
    def render(self, content):
        return json.dumps(
            content,
            ensure_ascii=False,
            indent=4,
            separators=(", ", ": ")
        ).encode("utf-8")