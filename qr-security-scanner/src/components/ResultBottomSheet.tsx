import React from 'react';
import { View, Text, StyleSheet, Button } from 'react-native';

const ResultBottomSheet: React.FC<{ result: string; onClose: () => void }> = ({ result, onClose }) => {
    return (
        <View style={styles.container}>
            <Text style={styles.resultText}>{result}</Text>
            <Button title="Close" onPress={onClose} />
        </View>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        padding: 20,
        backgroundColor: '#fff',
    },
    resultText: {
        fontSize: 18,
        marginBottom: 20,
    },
});

export default ResultBottomSheet;