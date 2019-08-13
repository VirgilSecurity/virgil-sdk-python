from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import sys

if __name__ == '__main__':
    template_loader = FileSystemLoader(searchpath="./")
    env = Environment(
        loader=template_loader,
        autoescape=select_autoescape(['html'])
    )

    template = env.get_template('ci/index.html')

    target_dir = sys.argv[1]
    version_list = list()
    for item in os.listdir(target_dir):
        item_full_path = os.path.join(target_dir, item)
        if os.path.isdir(item_full_path) and "git" not in item:
            version_list.append((item))

    open(os.path.join(target_dir, "index.html"), "w").write(template.render(version_dirs=version_list))
