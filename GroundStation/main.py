import sys
from PyQt5.QtWidgets import QApplication
from GroundStationGUI import GroundStationGUI
from GroundStation import GroundStation

if __name__ == '__main__':
    # Crea una instancia de QApplication, que es necesaria para cualquier aplicación PyQt
    app = QApplication(sys.argv)
    
    # Crea una instancia de la interfaz gráfica de la estación de tierra
    gui = GroundStationGUI()
    
    # Crea una instancia de GroundStation y le pasa la GUI para que pueda actualizarla
    ground_station = GroundStation(gui)
    
    # Inicia el hilo de la estación de tierra para comenzar su funcionamiento (recepción y procesamiento de datos)
    ground_station.start()
    
    # Muestra la interfaz gráfica
    gui.show()
    
    # Entra en el bucle de eventos principal de la aplicación, lo que permite que la GUI responda a las interacciones del usuario
    sys.exit(app.exec_())