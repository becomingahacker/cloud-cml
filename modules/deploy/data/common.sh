CONFIG_FILE="/etc/virl2-base-config.yml"

function is_controller() {
    [[ -r "$CONFIG_FILE" ]] && egrep -qi '"?is_controller"?: true' "$CONFIG_FILE"
}
