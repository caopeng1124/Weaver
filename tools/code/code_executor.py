"""Provider-neutral Python execution; never executes generated code on the host."""

from typing import Any

from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool

from tools.sandbox.permissions import authorize


@tool
def execute_python_code(code: str, config: RunnableConfig) -> dict[str, Any]:
    """Execute Python in the current sandbox. Save artifacts under /workspace.

    Files persist across calls in the same session. Use savefig to export charts.
    """
    context = authorize("sandbox.execute", config, "execute_python_code", {"code": code})
    from tools.sandbox.local_service import get_local_service

    result = get_local_service().execute(context, ["python3", "-u", "-"], stdin=code.encode())
    return {**result, "error": result["stderr"] if not result["success"] else None, "image": None}


def create_visualization(
    data: dict[str, Any], chart_type: str = "bar", *, config: RunnableConfig | None = None
) -> dict[str, Any]:
    """
    Helper function to create data visualizations.

    Args:
        data: Data to visualize
        chart_type: Type of chart (bar, line, pie, scatter)

    Returns:
        Execution result with generated chart
    """
    # Generate matplotlib code based on chart type
    code_template = f"""
import matplotlib.pyplot as plt
import numpy as np

# Your data
data = {data}

# Create chart
plt.figure(figsize=(10, 6))
# Add chart code here based on chart_type: {chart_type}
plt.title('Generated Chart')
plt.tight_layout()
plt.show()
"""

    return execute_python_code.invoke({"code": code_template}, config=config)
