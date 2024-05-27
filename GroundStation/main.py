import sys
from PyQt5.QtWidgets import QApplication
from GroundStationGUI import GroundStationGUI
from GroundStation import GroundStation

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = GroundStationGUI()
    ground_station = GroundStation(gui)
    ground_station.start()
    gui.show()
    sys.exit(app.exec_())