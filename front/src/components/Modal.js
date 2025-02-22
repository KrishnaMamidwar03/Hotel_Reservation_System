// components/Modal.js
import React from 'react';
import Modal from 'react-modal';

Modal.setAppElement('#root'); // For accessibility

const CustomModal = ({ isOpen, onRequestClose, children }) => {
  return (
    <Modal
      isOpen={isOpen}
      onRequestClose={onRequestClose}
      className="modal-content"
      overlayClassName="modal-overlay"
      closeTimeoutMS={300}
    >
      <div className="modal-header">
        <button onClick={onRequestClose} className="modal-close-button">
          &times;
        </button>
      </div>
      <div className="modal-body">
        {children}
      </div>
    </Modal>
  );
};

export default CustomModal;
