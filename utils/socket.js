let io = null;

export const initSocket = (_io) => {
  io = _io;
};

export const getIO = () => {
  if (!io) {
    throw new Error("Socket.io not initialized!");
  }
  return io;
};
