document.addEventListener('DOMContentLoaded', function () {
// Asegurarse de que solo se ejecute cuando se está en la página de gestión
    if (window.location.pathname === '/gestion') {
        const offenseIdInput = document.getElementById('offenseId');
        const closingReasonSelect = document.getElementById('closingReason');
        const noteInput = document.getElementById('note');
        const closeButton = document.getElementById('closeButton');
        const loadingIndicator = document.getElementById('loading');
        
        // Cargar las razones de cierre en el combo box
        fetch('/api/get_closing_reasons')
            .then(response => response.json())
            .then(data => {
                if (data && Array.isArray(data)) {
                    const options = data.map(reason => 
                        `<option value="${reason.id}">${reason.text}</option>`
                    );
                    closingReasonSelect.innerHTML = options.join('');
                } else {
                    alert("Error al obtener las razones de cierre");
                }
            })
            .catch(error => {
                console.error("Error al cargar las razones de cierre:", error);
            });

        // Manejo del evento de clic para cerrar ofensas
        closeButton.addEventListener('click', function () {
            const offenseId = offenseIdInput.value;
            const reasonId = closingReasonSelect.value;
            const note = noteInput.value;

            const payload = {
                offense_id: offenseId,
                reason_id: reasonId,
                note: note
            };

            loadingIndicator.style.display = 'block'; // Mostrar el indicador de carga

            fetch('/api/close_offense', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    alert(data.message);
                } else {
                    alert(data.error || "Error desconocido");
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert("Ocurrió un error al intentar cerrar la ofensa");
            })
            .finally(() => {
                loadingIndicator.style.display = 'none'; // Ocultar el indicador de carga
            });
        });
    }
});