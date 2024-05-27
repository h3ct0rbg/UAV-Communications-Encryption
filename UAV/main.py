import sys
from PyQt5.QtWidgets import QApplication
from UAVGUI import UAVGUI
from UAV import UAV

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = UAVGUI()
    uav = UAV(gui)
    uav.start()
    gui.show()
    sys.exit(app.exec_())