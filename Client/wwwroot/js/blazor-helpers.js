window.blazorHelpers = {
    scrollPosition: (elementId) => {
        var element = document.getElementById(elementId);

        if (element) {
            return Math.floor((element.clientHeight + element.scrollTop)/element.scrollHeight);
        }
    },

    scrollToEnd: (elementId) => {
        var element = document.getElementById(elementId);

        if (element) {
            element.scrollTo(0, element.scrollHeight);
        }
    }
};