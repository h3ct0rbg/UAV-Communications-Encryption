import sys
from PyQt5.QtWidgets import QApplication
from UAVGUI import UAVGUI
from UAV import UAV

if __name__ == '__main__':
    # Crea una instancia de QApplication, que es necesaria para cualquier aplicación PyQt
    app = QApplication(sys.argv)
    
    # Crea una instancia de la interfaz gráfica del UAV
    gui = UAVGUI()
    
    # Crea una instancia del UAV y le pasa la GUI para que pueda actualizarla
    uav = UAV(gui)
    
    # Inicia el hilo del UAV para comenzar su funcionamiento (envío de matrices encriptadas)
    uav.start()
    
    # Muestra la interfaz gráfica
    gui.show()
    
    # Entra en el bucle de eventos principal de la aplicación, lo que permite que la GUI responda a las interacciones del usuario
    sys.exit(app.exec_())