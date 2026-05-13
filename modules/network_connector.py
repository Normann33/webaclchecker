import logging
from typing import Optional, Dict, Any
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

logger = logging.getLogger(__name__)


class NetmikoConnector:
    """
    Абстракция сетевого подключения на базе netmiko.
    Реализует протокол контекстного менеджера для безопасного управления сессией.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        device_type: str = "cisco_ios",
        port: int = 22,
        secret: Optional[str] = None,
        timeout: int = 10,
        **netmiko_kwargs: Any
    ):
        self.host = host
        self.username = username
        self.password = password
        self.device_type = device_type
        self.port = port
        self.secret = secret
        self.timeout = timeout
        self.netmiko_kwargs = netmiko_kwargs
        
        self._connection: Optional[ConnectHandler] = None

    def __enter__(self) -> "NetmikoConnector":
        self.connect()
        return self

    def __exit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]) -> bool:
        self.disconnect()
        return False  # Не подавляем исключения

    def connect(self) -> None:
        """Устанавливает SSH-сессию. Повторный вызов без отключения игнорируется."""
        if self._connection and self._is_alive():
            return

        conn_params = {
            "device_type": self.device_type,
            "host": self.host,
            "username": self.username,
            "password": self.password,
            "port": self.port,
            "secret": self.secret,
            "timeout": self.timeout,
            **self.netmiko_kwargs
        }

        logger.info(f"Connecting to {self.host}:{self.port} (device_type={self.device_type})")
        try:
            self._connection = ConnectHandler(**conn_params)
            logger.info(f"Successfully connected to {self.host}")
        except NetmikoTimeoutException as e:
            logger.error(f"Connection timeout for {self.host}: {e}")
            raise
        except NetmikoAuthenticationException as e:
            logger.error(f"Authentication failed for {self.host}: {e}")
            raise

    def disconnect(self) -> None:
        """Корректно закрывает сессию."""
        if not self._connection:
            return

        try:
            if self._is_alive():
                self._connection.disconnect()
            logger.info(f"Disconnected from {self.host}")
        except Exception as e:
            logger.warning(f"Error during disconnect from {self.host}: {e}")
        finally:
            self._connection = None
            
    def enable(self, secret: Optional[str] = None) -> str:
        """
        Переводит сессию в привилегированный режим (enable).
        Использует secret из инициализации или переопределяет его на лету.
        """
        if not self._connection or not self._is_alive():
            raise RuntimeError(f"No active connection to {self.host}")

        try:
            # Если передан новый secret, динамически обновляем его в сессии
            if secret:
                self._connection.secret = secret
            
            # Netmiko сам возьмёт значение из self._connection.secret
            self._connection.enable()
            
            new_prompt = self._connection.find_prompt()
            logger.info(f"Entered enable mode on {self.host}. Prompt: {new_prompt}")
            return new_prompt
            
        except Exception as e:
            logger.error(f"Enable failed on {self.host}: {e}")
            raise
            
        except Exception as e:
            logger.error(f"Enable failed on {self.host}: {e}")
            raise

    def send_command(self, command: str, **kwargs: Any) -> str:
        """Выполняет команду на устройстве и возвращает вывод."""
        if not self._connection or not self._is_alive():
            raise RuntimeError(
                f"No active connection to {self.host}. Use 'with NetmikoConnector(...) as conn:'"
            )
        try:
            return self._connection.send_command(command, **kwargs)
        except Exception as e:
            logger.error(f"Command execution failed on {self.host} ('{command}'): {e}")
            raise
        
    # network_connector.py (добавьте в класс NetmikoConnector)

    def find_prompt(self) -> str:
        """Возвращает текущий промпт устройства (например, 'Router#' или 'Switch(config)#')"""
        if not self._connection or not self._is_alive():
            raise RuntimeError(f"No active connection to {self.host}")
        return self._connection.find_prompt()

    def _is_alive(self) -> bool:
        """Безопасная проверка статуса соединения."""
        try:
            return self._connection.is_alive() if self._connection else False
        except Exception:
            return False

    @property
    def host_ip(self) -> str:
        return self.host

    @property
    def is_connected(self) -> bool:
        return self._is_alive()