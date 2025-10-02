document.addEventListener('DOMContentLoaded', () => {
    let currentPage = 1;
    const perPage = 10;
    let sortColumn = 'Risk Number';
    let sortDirection = 'asc';

    // Chart initialization (replace with actual data from /api/risks)
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: 'top' },
            tooltip: { enabled: true }
        }
    };

    // Update metrics cards with risk data
    function updateMetricsCards(risks) {
        if (!risks || !Array.isArray(risks)) {
            console.log('No risk data available for metrics');
            // Set default values when no data
            document.getElementById('highRiskCount').textContent = '0';
            document.getElementById('overdueCount').textContent = '0';
            document.getElementById('totalRiskCount').textContent = '0';
            document.getElementById('riskTrend').textContent = 'N/A';
            return;
        }

        console.log('DEBUG: Updating metrics with', risks.length, 'risks');
        console.log('DEBUG: Sample risk data:', risks[0]);

        // Count high risk items (Inherent Rating = High or Extreme)
        const highRiskCount = risks.filter(risk => {
            const inherentRating = risk['Inherent Rating'] || '';
            return inherentRating === 'High' || inherentRating === 'Extreme';
        }).length;

        // Count overdue items - check multiple possible date fields
        const overdueCount = risks.filter(risk => {
            const dueDate = risk['Due Date'];
            if (dueDate) {
                const due = new Date(dueDate);
                const now = new Date();
                now.setHours(0, 0, 0, 0);
                return due < now;
            }
            return false;
        }).length;

        // Total risk count
        const totalRiskCount = risks.length;

        // Calculate risk trend based on residual vs inherent exposure
        let improvingCount = 0;
        let decliningCount = 0;
        risks.forEach(risk => {
            const inherentRating = risk['Inherent Rating'] || '';
            const residualExposure = risk['Residual Exposure (New)'] || '';

            // Map inherent rating to numeric value
            const inherentValue = {
                'Extreme': 4,
                'High': 3,
                'Medium': 2,
                'Low': 1
            }[inherentRating] || 0;

            // Map residual exposure to numeric value
            const residualValue = {
                'Priority 1': 4,
                'Priority 2': 3,
                'Priority 3': 2,
                'Priority 4': 1,
                'Priority 5': 0
            }[residualExposure] || 0;

            if (residualValue < inherentValue) {
                improvingCount++;
            } else if (residualValue > inherentValue) {
                decliningCount++;
            }
        });

        // Determine trend
        let trendText = 'Stable';
        let trendClass = 'text-gray-600';
        if (improvingCount > decliningCount * 1.5) {
            trendText = 'Improving';
            trendClass = 'text-green-600';
        } else if (decliningCount > improvingCount * 1.5) {
            trendText = 'Worsening';
            trendClass = 'text-red-600';
        }

        // Update the DOM elements
        const highRiskElement = document.getElementById('highRiskCount');
        const overdueElement = document.getElementById('overdueCount');
        const totalRiskElement = document.getElementById('totalRiskCount');
        const riskTrendElement = document.getElementById('riskTrend');
        const lastUpdatedElement = document.getElementById('lastUpdated');

        if (highRiskElement) highRiskElement.textContent = highRiskCount;
        if (overdueElement) overdueElement.textContent = overdueCount;
        if (totalRiskElement) totalRiskElement.textContent = totalRiskCount;
        if (riskTrendElement) {
            riskTrendElement.textContent = trendText;
            riskTrendElement.className = `text-lg font-semibold ${trendClass}`;
        }
        if (lastUpdatedElement) {
            const now = new Date();
            lastUpdatedElement.textContent = now.toLocaleTimeString();
        }

        console.log(`Metrics updated: ${highRiskCount} high risk, ${overdueCount} overdue, ${totalRiskCount} total, trend: ${trendText}`);
    }

    // Initialize charts using the existing D3.js functions from base.html
    drawInherentRatingChart();
    drawResidualExposureChart();
    drawDueDateStatusChart();
    
    // Fetch data for Impact vs Likelihood chart and metrics
    function loadDashboardData() {
        // Show loading state
        document.getElementById('highRiskCount').textContent = '...';
        document.getElementById('overdueCount').textContent = '...';
        document.getElementById('totalRiskCount').textContent = '...';
        document.getElementById('riskTrend').textContent = '...';

        fetch('/api/all_risks_for_dashboard')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('Risk data for dashboard:', data);
                console.log('Total risks loaded:', data.length);
                if (data.length > 0) {
                    console.log('Sample risk for Impact/Likelihood:', data[0]);
                }

                // Create Impact vs Likelihood chart
                createImpactLikelihoodChart(data);

                // Update metrics cards with all risks
                updateMetricsCards(data);
            })
            .catch(error => {
                console.error('Error fetching risks for dashboard:', error);
                // Show error message in chart container
                const container = document.getElementById('impactLikelihoodChart');
                if (container) {
                    container.innerHTML = '<div class="flex items-center justify-center h-full text-gray-500"><p>Error loading chart data</p></div>';
                }
                // Reset metrics to 0
                updateMetricsCards([]);
            });
    }

    // Load dashboard data on page load
    loadDashboardData();

    // Load risks with pagination and sorting
    function loadRisks(query = '', primaryOwner = '', secondaryOwner = '', page = 1, column = sortColumn, direction = sortDirection) {
        // Use the existing endpoint that works
        fetch('/api/all_risks_for_dashboard')
            .then(response => response.json())
            .then(allRisks => {
                // Apply client-side filtering since the endpoint doesn't support all the parameters
                let filteredRisks = allRisks;
                
                // Apply search filter
                if (query) {
                    filteredRisks = filteredRisks.filter(risk => 
                        Object.values(risk).some(value => 
                            value && value.toString().toLowerCase().includes(query.toLowerCase())
                        )
                    );
                }
                
                // Apply primary owner filter
                if (primaryOwner && primaryOwner !== 'all_risks') {
                    filteredRisks = filteredRisks.filter(risk => 
                        risk['Risk Owner'] === primaryOwner
                    );
                }
                
                // Apply secondary owner filter
                if (secondaryOwner) {
                    filteredRisks = filteredRisks.filter(risk => 
                        risk['Secondary Risk Owner'] === secondaryOwner
                    );
                }
                
                // Apply sorting
                if (column && sortDirection) {
                    filteredRisks.sort((a, b) => {
                        let aVal = a[column] || '';
                        let bVal = b[column] || '';
                        
                        // Handle numeric sorting for specific columns
                        if (['Impact', 'Likelihood', 'Inherent Exposure'].includes(column)) {
                            aVal = parseInt(aVal) || 0;
                            bVal = parseInt(bVal) || 0;
                        }
                        
                        if (sortDirection === 'asc') {
                            return aVal > bVal ? 1 : -1;
                        } else {
                            return aVal < bVal ? 1 : -1;
                        }
                    });
                }
                
                // Apply pagination
                const startIndex = (page - 1) * perPage;
                const endIndex = startIndex + perPage;
                const paginatedRisks = filteredRisks.slice(startIndex, endIndex);
                
                const tbody = document.getElementById('riskTableBody');
                tbody.innerHTML = '';
                if (paginatedRisks.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="100%" class="px-6 py-4 text-center text-gray-500">No risks found.</td></tr>';
                    return;
                }
                paginatedRisks.forEach(risk => {
                    const tr = document.createElement('tr');
                    tr.className = 'hover:bg-gray-50 transition-all duration-200';
                    
                    // Get selected columns from header
                    const headerCells = document.querySelectorAll('#riskTableHeaderRow th');
                    const selectedColumns = Array.from(headerCells).slice(0, -1).map(th => 
                        th.dataset.column || th.textContent.trim()
                    );
                    
                    // Generate table cells based on selected columns
                    let cellsHtml = '';
                    selectedColumns.forEach(col => {
                        if (col === 'Progress') {
                            const progress = calculateRiskProgress(risk);
                            const progressBarHtml = createProgressBar(progress);
                            cellsHtml += `<td class="px-6 py-4 text-sm">${progressBarHtml}</td>`;
                        } else {
                            cellsHtml += `<td class="px-6 py-4 text-sm text-gray-700">${risk[col] || ''}</td>`;
                        }
                    });
                    
                    tr.innerHTML = `
                        ${cellsHtml}
                        <td class="px-6 py-4 text-sm">
                            <a href="/risk/edit/${risk.id}" class="text-blue-600 hover:underline">Edit</a>
                            {% if current_user.role in ['ADMINISTRATOR', 'EDITOR'] %}
                            | <a href="#" class="text-red-600 hover:underline" onclick="confirmDelete(${risk.id})">Delete</a>
                            {% endif %}
                        </td>`;
                    tbody.appendChild(tr);
                });
                
                // Update table info
                updateTableInfo(filteredRisks.length, allRisks.length, page, perPage);

                // Update metrics cards with all risks (not filtered)
                updateMetricsCards(allRisks);
                
                // Show action buttons once data is loaded
                document.getElementById('actionButtonsContainer').style.display = 'flex';
                
                // Update pagination info with correct data
                const totalPages = Math.ceil(filteredRisks.length / perPage);
                const pageInfo = document.getElementById('pageInfo');
                const prevPage = document.getElementById('prevPage');
                const nextPage = document.getElementById('nextPage');

                if (pageInfo) pageInfo.textContent = `Page ${page} of ${totalPages}`;
                if (prevPage) prevPage.disabled = page === 1;
                if (nextPage) nextPage.disabled = page === totalPages;
            })
            .catch(error => console.error('Error loading risks:', error));
    }

    // Populate owner dropdowns
    fetch('/api/risk_owners')
        .then(response => response.json())
        .then(owners => {
            const primarySelect = document.getElementById('primaryOwnerSelect');
            const secondarySelect = document.getElementById('secondaryOwnerSelect');
            owners.forEach(owner => {
                primarySelect.innerHTML += `<option value="${owner}">${owner}</option>`;
                secondarySelect.innerHTML += `<option value="${owner}">${owner}</option>`;
            });
        });

    // Populate column selection modal
    fetch('/api/all_risks')
        .then(response => response.json())
        .then(data => {
            const columns = data.length > 0 ? Object.keys(data[0]) : [];
            const modal = document.getElementById('modalColumnCheckboxes');
            modal.innerHTML = '';
            columns.forEach(col => {
                modal.innerHTML += `
                    <label class="flex items-center text-gray-700">
                        <input type="checkbox" value="${col}" class="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded" checked> ${col}
                    </label>`;
            });
            // Add Progress column to the available columns
            modal.innerHTML += `
                <label class="flex items-center text-gray-700">
                    <input type="checkbox" value="Progress" class="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded" checked> Progress
                </label>`;
            
            // Apply column selection
            document.getElementById('applyColumnSelectionBtn').addEventListener('click', () => {
                const selectedColumns = Array.from(modal.querySelectorAll('input:checked')).map(input => input.value);
                const headerRow = document.getElementById('riskTableHeaderRow');
                headerRow.innerHTML = selectedColumns.map(col => `
                    <th class="px-6 py-3 ${col === 'Progress' ? '' : 'cursor-pointer'}" ${col === 'Progress' ? '' : `data-column="${col}"`}>
                        ${col} ${col === 'Progress' ? '' : `<span class="sort-icon">${sortColumn === col ? (sortDirection === 'asc' ? '↑' : '↓') : ''}</span>`}
                    </th>`).join('') + `<th class="px-6 py-3">Actions</th>`;
                
                // Add sorting event listeners (exclude Progress column from sorting)
                document.querySelectorAll('#riskTableHeaderRow th[data-column]').forEach(th => {
                    th.addEventListener('click', () => {
                        const column = th.dataset.column;
                        sortDirection = sortColumn === column && sortDirection === 'asc' ? 'desc' : 'asc';
                        sortColumn = column;
                        loadRisks(
                            document.getElementById('riskSearch').value,
                            document.getElementById('primaryOwnerSelect').value,
                            document.getElementById('secondaryOwnerSelect').value,
                            currentPage,
                            sortColumn,
                            sortDirection
                        );
                        document.querySelectorAll('.sort-icon').forEach(icon => icon.textContent = '');
                        th.querySelector('.sort-icon').textContent = sortDirection === 'asc' ? '↑' : '↓';
                    });
                });
                loadRisks();
                bootstrap.Modal.getInstance(document.getElementById('columnSelectionModal')).hide();
            });
        });

    // Event listeners
    // Event listeners with null checks
    const primaryOwnerSelect = document.getElementById('primaryOwnerSelect');
    const secondaryOwnerSelect = document.getElementById('secondaryOwnerSelect');
    const riskSearch = document.getElementById('riskSearch');
    const prevPage = document.getElementById('prevPage');
    const nextPage = document.getElementById('nextPage');
    const exportPdfButton = document.getElementById('exportPdfButton');

    if (primaryOwnerSelect) {
        primaryOwnerSelect.addEventListener('change', (e) => {
            currentPage = 1;
            loadRisks(riskSearch?.value || '', e.target.value, secondaryOwnerSelect?.value || '');
        });
    }

    if (secondaryOwnerSelect) {
        secondaryOwnerSelect.addEventListener('change', (e) => {
            currentPage = 1;
            loadRisks(riskSearch?.value || '', primaryOwnerSelect?.value || '', e.target.value);
        });
    }

    if (riskSearch) {
        riskSearch.addEventListener('input', (e) => {
            currentPage = 1;
            loadRisks(e.target.value, primaryOwnerSelect?.value || '', secondaryOwnerSelect?.value || '');
        });
    }

    if (prevPage) {
        prevPage.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                loadRisks(riskSearch?.value || '', primaryOwnerSelect?.value || '', secondaryOwnerSelect?.value || '', currentPage);
            }
        });
    }

    if (nextPage) {
        nextPage.addEventListener('click', () => {
            currentPage++;
            loadRisks(riskSearch?.value || '', primaryOwnerSelect?.value || '', secondaryOwnerSelect?.value || '', currentPage);
        });
    }

    if (exportPdfButton) {
        exportPdfButton.addEventListener('click', () => {
            exportToPDF();
        });
    }

    // Update table info display
    function updateTableInfo(filteredCount, totalCount, currentPage, perPage) {
        const startIndex = (currentPage - 1) * perPage + 1;
        const endIndex = Math.min(currentPage * perPage, filteredCount);
        const tableInfo = document.getElementById('tableInfo');
        if (tableInfo) {
            if (filteredCount === 0) {
                tableInfo.textContent = '0 of 0';
            } else {
                tableInfo.textContent = `${startIndex}-${endIndex} of ${filteredCount}`;
            }
        }
    }

    function confirmDelete(riskId) {
        const modal = new bootstrap.Modal(document.getElementById('confirmDeleteModal'));
        modal.show();
        document.getElementById('confirmDeleteBtn').onclick = () => {
            fetch(`/api/risk/${riskId}/delete`, { method: 'POST' })
                .then(() => {
                    modal.hide();
                    loadRisks();
                })
                .catch(error => console.error('Error deleting risk:', error));
        };
    }

    // Calculate risk progress based on various factors
    function calculateRiskProgress(risk) {
        let progress = 0;
        let totalFactors = 0;

        // Factor 1: Risk identification (always present if risk exists)
        progress += 20;
        totalFactors++;

        // Factor 2: Risk assessment (Impact and Likelihood)
        if (risk['Impact'] && risk['Likelihood']) {
            progress += 20;
        }
        totalFactors++;

        // Factor 3: Control effectiveness assessment
        if (risk['Control Effectiveness: How effective is the control in addressi']) {
            progress += 20;
        }
        totalFactors++;

        // Factor 4: Action owner assignment
        if (risk['Action Owner']) {
            progress += 20;
        }
        totalFactors++;

        // Factor 5: Status completion
        const status = risk['Status'] || '';
        if (status.toLowerCase().includes('complete') || status.toLowerCase().includes('closed')) {
            progress += 20;
        } else if (status.toLowerCase().includes('progress') || status.toLowerCase().includes('ongoing')) {
            progress += 10;
        } else if (status) {
            progress += 5;
        }
        totalFactors++;

        return Math.min(progress, 100);
    }

    // Create progress bar HTML with percentage text
    function createProgressBar(percentage) {
        const progressColor = getProgressColor(percentage);
        return `
            <div class="w-full bg-gray-200 rounded-full h-6 relative">
                <div class="bg-${progressColor} h-6 rounded-full transition-all duration-300 ease-in-out flex items-center justify-center" style="width: ${percentage}%">
                </div>
                ${percentage < 50 ? `<span class="absolute inset-0 flex items-center justify-center text-xs font-semibold text-gray-700">${percentage}%</span>` : ''}
            </div>
        `;
    }

    // Get progress bar color based on percentage
    function getProgressColor(percentage) {
        if (percentage >= 80) return 'green-500';
        if (percentage >= 60) return 'blue-500';
        if (percentage >= 40) return 'yellow-500';
        if (percentage >= 20) return 'orange-500';
        return 'red-500';
    }

    // PDF Export Function
    async function exportToPDF() {
        try {
            // Show loading indicator
            const exportBtn = document.getElementById('exportPdfButton');
            const originalText = exportBtn.textContent;
            exportBtn.textContent = 'Generating PDF...';
            exportBtn.disabled = true;

            // Check if jsPDF is available
            if (!window.jspdf || !window.jspdf.jsPDF) {
                alert('PDF library is still loading. Please wait a moment and try again.');
                exportBtn.textContent = originalText;
                exportBtn.disabled = false;
                return;
            }
            
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF('l', 'mm', 'a4'); // landscape orientation
            
            // Get current filter values safely
            const searchValue = document.getElementById('riskSearch')?.value || '';
            const primaryOwnerValue = document.getElementById('primaryOwnerSelect')?.value || '';
            const secondaryOwnerValue = document.getElementById('secondaryOwnerSelect')?.value || '';
            
            // Get all risk data using the correct endpoint
            const response = await fetch('/api/all_risks_for_dashboard');
            const data = await response.json();

            // Handle the response format - data is directly an array
            const risks = Array.isArray(data) ? data : (data.risks || []);
            
            console.log('PDF Export - Risk data:', risks.length, 'risks found');

            // PDF Configuration
            const pageWidth = doc.internal.pageSize.getWidth();
            const pageHeight = doc.internal.pageSize.getHeight();
            const margin = 20;
            let yPosition = margin;

            // Header
            doc.setFontSize(20);
            doc.setFont('helvetica', 'bold');
            doc.text('Enterprise Risk Management Report', margin, yPosition);
            yPosition += 10;

            // Date and summary
            doc.setFontSize(12);
            doc.setFont('helvetica', 'normal');
            doc.text(`Generated on: ${new Date().toLocaleDateString()}`, margin, yPosition);
            yPosition += 6;
            doc.text(`Total Risks: ${risks.length}`, margin, yPosition);
            yPosition += 15;

            // Get selected columns from the table, with fallback to default columns
            let selectedColumns = [];
            const headerRow = document.getElementById('riskTableHeaderRow');
            if (headerRow) {
                selectedColumns = Array.from(headerRow.querySelectorAll('th[data-column]')).map(th => th.dataset.column);
            }
            
            if (selectedColumns.length === 0) {
                // Default columns if none selected or table not found
                selectedColumns = ['Risk Number', 'Risk Title', 'Primary Risk Owner', 'Inherent Rating', 'Residual Priority', 'Due Date'];
            }

            // Table setup
            const colWidth = (pageWidth - 2 * margin) / selectedColumns.length;
            const rowHeight = 8;

            // Table header
            doc.setFontSize(10);
            doc.setFont('helvetica', 'bold');
            doc.setFillColor(240, 240, 240);
            doc.rect(margin, yPosition, pageWidth - 2 * margin, rowHeight, 'F');
            
            selectedColumns.forEach((col, index) => {
                const xPos = margin + (index * colWidth);
                doc.text(col, xPos + 2, yPosition + 5);
            });
            yPosition += rowHeight;

            // Table rows
            doc.setFont('helvetica', 'normal');
            risks.forEach((risk, rowIndex) => {
                // Check if we need a new page
                if (yPosition + rowHeight > pageHeight - margin) {
                    doc.addPage();
                    yPosition = margin;
                    
                    // Repeat header on new page
                    doc.setFont('helvetica', 'bold');
                    doc.setFillColor(240, 240, 240);
                    doc.rect(margin, yPosition, pageWidth - 2 * margin, rowHeight, 'F');
                    selectedColumns.forEach((col, index) => {
                        const xPos = margin + (index * colWidth);
                        doc.text(col, xPos + 2, yPosition + 5);
                    });
                    yPosition += rowHeight;
                    doc.setFont('helvetica', 'normal');
                }

                // Alternate row colors
                if (rowIndex % 2 === 0) {
                    doc.setFillColor(250, 250, 250);
                    doc.rect(margin, yPosition, pageWidth - 2 * margin, rowHeight, 'F');
                }

                // Row data
                selectedColumns.forEach((col, index) => {
                    const xPos = margin + (index * colWidth);
                    let cellValue = risk[col] || '';
                    
                    // Handle different data types safely
                    if (cellValue === null || cellValue === undefined) {
                        cellValue = '';
                    } else if (typeof cellValue === 'object') {
                        cellValue = JSON.stringify(cellValue);
                    }
                    
                    // Truncate long text to fit in cell
                    const cellText = cellValue.toString();
                    if (cellText.length > 25) {
                        cellValue = cellText.substring(0, 22) + '...';
                    } else {
                        cellValue = cellText;
                    }
                    
                    doc.text(cellValue, xPos + 2, yPosition + 5);
                });
                yPosition += rowHeight;
            });

            // Add chart data summary on a new page
            doc.addPage();
            yPosition = margin;

            doc.setFontSize(16);
            doc.setFont('helvetica', 'bold');
            doc.text('Risk Analysis Summary', margin, yPosition);
            yPosition += 15;

            // Get chart data for summary
            const chartResponse = await fetch('/api/chart_data/inherent_residual');
            const chartData = await chartResponse.json();

            // Inherent Rating Summary
            doc.setFontSize(14);
            doc.text('Inherent Rating Distribution:', margin, yPosition);
            yPosition += 10;

            const inherentRatingCounts = {};
            chartData.forEach(item => {
                const rating = item.inherent_rating;
                if (rating && ['Low', 'Medium', 'High', 'Extreme'].includes(rating)) {
                    inherentRatingCounts[rating] = (inherentRatingCounts[rating] || 0) + item.count;
                }
            });

            doc.setFontSize(12);
            doc.setFont('helvetica', 'normal');
            Object.entries(inherentRatingCounts).forEach(([rating, count]) => {
                doc.text(`• ${rating}: ${count} risks`, margin + 10, yPosition);
                yPosition += 6;
            });

            yPosition += 10;

            // Residual Priority Summary
            doc.setFontSize(14);
            doc.setFont('helvetica', 'bold');
            doc.text('Residual Priority Distribution:', margin, yPosition);
            yPosition += 10;

            const residualPriorityCounts = {};
            chartData.forEach(item => {
                const priority = item.residual_exposure;
                if (priority && priority.startsWith('Priority')) {
                    residualPriorityCounts[priority] = (residualPriorityCounts[priority] || 0) + item.count;
                }
            });

            doc.setFontSize(12);
            doc.setFont('helvetica', 'normal');
            Object.entries(residualPriorityCounts).forEach(([priority, count]) => {
                doc.text(`• ${priority}: ${count} risks`, margin + 10, yPosition);
                yPosition += 6;
            });

            // Footer on each page
            const pageCount = doc.internal.getNumberOfPages();
            for (let i = 1; i <= pageCount; i++) {
                doc.setPage(i);
                doc.setFontSize(8);
                doc.setFont('helvetica', 'normal');
                doc.text(`Page ${i} of ${pageCount}`, pageWidth - margin - 20, pageHeight - 10);
                doc.text('Enterprise Risk Management System', margin, pageHeight - 10);
            }

            // Save the PDF
            const fileName = `Risk_Report_${new Date().toISOString().split('T')[0]}.pdf`;
            doc.save(fileName);

            // Show success message
            if (window.showCustomMessage) {
                window.showCustomMessage('PDF report generated successfully!', 'success');
            }

        } catch (error) {
            console.error('Error generating PDF:', error);
            console.error('Error details:', error.message, error.stack);
            
            let errorMessage = 'Failed to generate PDF report. ';
            if (error.message.includes('jsPDF')) {
                errorMessage += 'jsPDF library not loaded properly.';
            } else if (error.message.includes('fetch')) {
                errorMessage += 'Unable to fetch risk data.';
            } else {
                errorMessage += `Error: ${error.message}`;
            }
            
            if (window.showCustomMessage) {
                window.showCustomMessage(errorMessage, 'danger');
            } else {
                alert(errorMessage);
            }
        } finally {
            // Reset button
            const exportBtn = document.getElementById('exportPdfButton');
            if (exportBtn) {
                exportBtn.textContent = 'Export PDF';
                exportBtn.disabled = false;
            }
        }
    }

    // Make exportToPDF available globally
    window.exportToPDF = exportToPDF;

    // Create Impact vs Likelihood chart function
    function createImpactLikelihoodChart(risks) {
        const container = document.getElementById('impactLikelihoodChart');
        if (!container) {
            console.error('Impact vs Likelihood chart container not found');
            return;
        }
        
        // Validate input data
        if (!risks || !Array.isArray(risks) || risks.length === 0) {
            container.innerHTML = '<div class="flex items-center justify-center h-full text-gray-500"><p>No risk data available for chart</p></div>';
            return;
        }
        
        container.innerHTML = ''; // Clear existing content

        const margin = { top: 40, right: 120, bottom: 80, left: 80 };
        const width = 800 - margin.left - margin.right;
        const height = 500 - margin.top - margin.bottom;

        // Create SVG
        const svg = d3.select(container)
            .append('svg')
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom)
            .attr('class', 'impact-likelihood-svg');

        const g = svg.append('g')
            .attr('transform', `translate(${margin.left},${margin.top})`);

        // Process data - group risks by Impact and Likelihood
        const riskMatrix = {};
        let validRisks = 0;
        let totalRisks = risks.length;
        
        risks.forEach(risk => {
            // Try different possible field names for Impact and Likelihood
            const impact = parseInt(risk['Impact'] || risk['impact'] || risk['Impact Rating'] || 0);
            const likelihood = parseInt(risk['Likelihood'] || risk['likelihood'] || risk['Likelihood Rating'] || 0);
            
            if (impact >= 1 && impact <= 5 && likelihood >= 1 && likelihood <= 5) {
                validRisks++;
                const key = `${impact}-${likelihood}`;
                if (!riskMatrix[key]) {
                    riskMatrix[key] = {
                        impact: impact,
                        likelihood: likelihood,
                        risks: [],
                        count: 0
                    };
                }
                riskMatrix[key].risks.push(risk);
                riskMatrix[key].count++;
            }
        });
        
        console.log(`Impact vs Likelihood Chart: ${validRisks} valid risks out of ${totalRisks} total risks`);
        console.log('Risk matrix data:', riskMatrix);
        
        // Show message if no valid data
        if (validRisks === 0) {
            container.innerHTML = '<div class="flex items-center justify-center h-full text-gray-500"><p>No risks with valid Impact and Likelihood values (1-5) found</p></div>';
            return;
        }

        // Create scales
        const xScale = d3.scaleLinear()
            .domain([0.5, 5.5])
            .range([0, width]);

        const yScale = d3.scaleLinear()
            .domain([0.5, 5.5])
            .range([height, 0]);

        // Color scale based on risk level (Impact * Likelihood)
        const colorScale = d3.scaleSequential(d3.interpolateRdYlGn)
            .domain([25, 1]); // Reverse scale: high values (red) to low values (green)

        // Create grid background
        for (let i = 1; i <= 5; i++) {
            for (let j = 1; j <= 5; j++) {
                const riskLevel = i * j;
                g.append('rect')
                    .attr('x', xScale(j - 0.4))
                    .attr('y', yScale(i + 0.4))
                    .attr('width', xScale(0.8) - xScale(0))
                    .attr('height', yScale(0) - yScale(0.8))
                    .attr('fill', colorScale(riskLevel))
                    .attr('opacity', 0.3)
                    .attr('stroke', '#fff')
                    .attr('stroke-width', 1);

                // Add risk level text in each cell
                g.append('text')
                    .attr('x', xScale(j))
                    .attr('y', yScale(i) + 5)
                    .attr('text-anchor', 'middle')
                    .attr('font-size', '10px')
                    .attr('fill', '#666')
                    .text(riskLevel);
            }
        }

        // Add data points (circles for each risk combination)
        Object.values(riskMatrix).forEach(item => {
            const riskLevel = item.impact * item.likelihood;
            const circleRadius = Math.sqrt(item.count) * 6 + 8; // Size based on count
            
            const circle = g.append('circle')
                .attr('cx', xScale(item.likelihood))
                .attr('cy', yScale(item.impact))
                .attr('r', circleRadius)
                .attr('fill', colorScale(riskLevel))
                .attr('stroke', '#333')
                .attr('stroke-width', 2)
                .attr('opacity', 0.9)
                .style('cursor', 'pointer');

            // Add count text on circles
            g.append('text')
                .attr('x', xScale(item.likelihood))
                .attr('y', yScale(item.impact) + 4)
                .attr('text-anchor', 'middle')
                .attr('font-size', circleRadius > 15 ? '14px' : '12px')
                .attr('font-weight', 'bold')
                .attr('fill', riskLevel > 15 ? 'white' : '#333')
                .style('pointer-events', 'none')
                .text(item.count);

            // Add interactive tooltip
            circle.append('title')
                .text(`Impact: ${item.impact}, Likelihood: ${item.likelihood}\nNumber of Risks: ${item.count}\nRisk Level: ${riskLevel}\n\nRisks:\n${item.risks.map(r => r['Risk Number'] || r['Risk Title'] || 'Unknown').slice(0, 5).join('\n')}${item.count > 5 ? '\n...' : ''}`);
            
            // Add hover effects
            circle
                .on('mouseover', function() {
                    d3.select(this)
                        .transition()
                        .duration(200)
                        .attr('r', circleRadius * 1.2)
                        .attr('opacity', 1);
                })
                .on('mouseout', function() {
                    d3.select(this)
                        .transition()
                        .duration(200)
                        .attr('r', circleRadius)
                        .attr('opacity', 0.9);
                });
        });

        // Add axes with custom styling
        const xAxis = g.append('g')
            .attr('transform', `translate(0,${height})`)
            .call(d3.axisBottom(xScale).tickValues([1, 2, 3, 4, 5]));
        
        xAxis.selectAll('text')
            .style('font-size', '12px')
            .style('font-weight', 'bold');

        const yAxis = g.append('g')
            .call(d3.axisLeft(yScale).tickValues([1, 2, 3, 4, 5]));
            
        yAxis.selectAll('text')
            .style('font-size', '12px')
            .style('font-weight', 'bold');

        // Add axis labels
        g.append('text')
            .attr('transform', 'rotate(-90)')
            .attr('y', 0 - margin.left + 20)
            .attr('x', 0 - (height / 2))
            .attr('dy', '1em')
            .style('text-anchor', 'middle')
            .style('font-size', '16px')
            .style('font-weight', 'bold')
            .style('fill', '#374151')
            .text('Impact →');

        g.append('text')
            .attr('transform', `translate(${width / 2}, ${height + margin.bottom - 20})`)
            .style('text-anchor', 'middle')
            .style('font-size', '16px')
            .style('font-weight', 'bold')
            .style('fill', '#374151')
            .text('← Likelihood →');

        // Add chart title with statistics
        g.append('text')
            .attr('x', width / 2)
            .attr('y', -20)
            .attr('text-anchor', 'middle')
            .style('font-size', '18px')
            .style('font-weight', 'bold')
            .style('fill', '#1F2937')
            .text(`Risk Matrix: ${validRisks} Risks Plotted (${Object.keys(riskMatrix).length} Unique Combinations)`);

        // Add legend
        const legend = g.append('g')
            .attr('transform', `translate(${width - 100}, 20)`);

        legend.append('text')
            .attr('x', 0)
            .attr('y', 0)
            .style('font-size', '12px')
            .style('font-weight', 'bold')
            .text('Risk Level');

        const legendScale = d3.scaleLinear()
            .domain([1, 25])
            .range([0, 80]);

        const legendAxis = d3.axisBottom(legendScale)
            .tickValues([1, 5, 10, 15, 20, 25]);

        legend.append('g')
            .attr('transform', 'translate(0, 30)')
            .call(legendAxis);

        // Add color gradient for legend
        const gradient = svg.append('defs')
            .append('linearGradient')
            .attr('id', 'risk-gradient')
            .attr('x1', '0%')
            .attr('x2', '100%');

        gradient.selectAll('stop')
            .data(d3.range(0, 1.1, 0.1))
            .enter().append('stop')
            .attr('offset', d => `${d * 100}%`)
            .attr('stop-color', d => colorScale(25 - d * 24));

        legend.append('rect')
            .attr('x', 0)
            .attr('y', 10)
            .attr('width', 80)
            .attr('height', 15)
            .style('fill', 'url(#risk-gradient)');
    }

    // Initial load
    loadRisks();
});